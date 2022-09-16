/* Copyright 2020 CLOUD&HEAT Technologies GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/template"

	corev1 "k8s.io/api/core/v1"

	"github.com/cloudandheat/ch-k8s-lbaas/internal/config"
	"github.com/cloudandheat/ch-k8s-lbaas/internal/model"
)

var (
	nftablesTemplate = template.Must(template.New("nftables.conf").Parse(`
{{ $cfg := . }}
table {{ .FilterTableType }} {{ .FilterTableName }} {
	chain {{ .FilterForwardChainName }} {
		{{ range $fwd := .Forwards }}
		{{ if ne ($fwd.IPBlocks | len) 0 }}
			{{- range $block := $fwd.IPBlocks }}
				{{- range $except := $block.Except}}
		ct mark {{ $fwd.Mark }} ip saddr {{ $except }} drop;
				{{- end }}
		ct mark {{ $fwd.Mark }} ip saddr {{ $block.Cidr }} accept;
			{{ end -}}
		{{ end -}}
		ct mark {{ $fwd.Mark }} {{ $fwd.DefaultPolicy }};
		{{ end }}
	}
}

table ip {{ .NATTableName }} {
	chain {{ .NATPreroutingChainName }} {
{{ range $fwd := .Forwards }}
{{ if ne ($fwd.DestinationAddresses | len) 0 }}
		ip daddr {{ $fwd.InboundIP }} {{ $fwd.Protocol }} dport {{ $fwd.InboundPort }} mark set {{ $fwd.Mark }} ct mark set meta mark dnat to numgen inc mod {{ $fwd.DestinationAddresses | len }} map {
{{- range $index, $daddr := $fwd.DestinationAddresses }}{{ $index }} : {{ $daddr }}, {{ end -}}
		} : {{ $fwd.DestinationPort }};
{{ end }}
{{ end }}
	}

	chain {{ .NATPostroutingChainName }} {
		{{ range $fwd := .Forwards }}
		mark {{ $fwd.Mark }} masquerade;
		{{ end }}
	}
}
`))

	ErrProtocolNotSupported = fmt.Errorf("Protocol is not supported")
)

type nftablesIPBlock struct {
	Cidr   string
	Except []string
}

type nftablesForward struct {
	Protocol             string
	InboundIP            string
	InboundPort          int32
	DestinationAddresses []string
	DestinationPort      int32
	DefaultPolicy        string
	Mark                 int32
	IPBlocks             []model.AllowedIPBlock // TODO: Use nftablesIPBlock instead of model
}

type nftablesConfig struct {
	FilterTableType         string
	FilterTableName         string
	FilterForwardChainName  string
	NATTableName            string
	NATPostroutingChainName string
	NATPreroutingChainName  string
	Forwards                []nftablesForward
}

type NftablesGenerator struct {
	Cfg config.Nftables
}

func copyAddresses(in []string) []string {
	result := make([]string, len(in))
	copy(result, in)
	return result
}

// func copyAddressBlocks(in []model.AllowedIPBlock) []nftablesIPBlock {
// 	result := make([]nftablesIPBlock, len(in))
// 	for i, block := range in {
// 		result[i].Cidr = block.Cidr
// 		copy(result[i].Except, block.Except)
// 	}
// 	return result
// }

// Maps from k8s.io/api/core/v1.Protocol objects to strings understood by nftables
func (g *NftablesGenerator) mapProtocol(k8sproto corev1.Protocol) (string, error) {
	switch k8sproto {
	case corev1.ProtocolTCP:
		return "tcp", nil
	case corev1.ProtocolUDP:
		return "udp", nil
	default:
		return "", ErrProtocolNotSupported
	}
}

// Generates a config suitable for nftablesTemplate from a LoadBalancer model
func (g *NftablesGenerator) GenerateStructuredConfig(m *model.LoadBalancer) (*nftablesConfig, error) {
	result := &nftablesConfig{
		FilterTableName:         g.Cfg.FilterTableName,
		FilterTableType:         g.Cfg.FilterTableType,
		FilterForwardChainName:  g.Cfg.FilterForwardChainName,
		NATTableName:            g.Cfg.NATTableName,
		NATPostroutingChainName: g.Cfg.NATPostroutingChainName,
		NATPreroutingChainName:  g.Cfg.NATPreroutingChainName,
		Forwards:                []nftablesForward{},
	}

	var mark int32 = 0
	for _, ingress := range m.Ingress {
		for _, port := range ingress.Ports {
			mark += 1

			mappedProtocol, err := g.mapProtocol(port.Protocol)
			if err != nil {
				return nil, err
			}

			addrs := copyAddresses(port.DestinationAddresses)
			sort.Strings(addrs)

			// ipblocks := copyAddressBlocks(port.AllowedIPBlocks)

			var default_policy string
			switch port.DefaultPolicy {
			case "allow", "drop":
				default_policy = port.DefaultPolicy
			case "":
				if len(port.AllowedIPBlocks) == 0 {
					default_policy = "allow"
				} else {
					default_policy = "drop"
				}
			default:
				return nil, fmt.Errorf("Invalid value for DefaultPolicy: %s", default_policy)
			}

			sort.SliceStable(port.AllowedIPBlocks, func(i, j int) bool {
				blockA := port.AllowedIPBlocks[i]
				blockB := port.AllowedIPBlocks[j]

				getHostBytes := func(addr string) (hostBytes int) {
					s := strings.Split(addr, "/")
					r, err := strconv.Atoi(s[1])
					if err != nil {
						panic("kapuuuut")
						// TODO: what if it fails? .. wee need to check incoming data earlier
					}
					return r
				}

				isSmallerCidr := getHostBytes(blockA.Cidr) > getHostBytes(blockB.Cidr)

				return isSmallerCidr
			})

			result.Forwards = append(result.Forwards, nftablesForward{
				Protocol:             mappedProtocol,
				InboundIP:            ingress.Address,
				InboundPort:          port.InboundPort,
				DestinationAddresses: addrs,
				DestinationPort:      port.DestinationPort,
				DefaultPolicy:        default_policy,
				Mark:                 mark,
				IPBlocks:             port.AllowedIPBlocks,
			})
		}
	}

	sort.SliceStable(result.Forwards, func(i, j int) bool {
		fwdA := &result.Forwards[i]
		fwdB := &result.Forwards[j]
		isLess := fwdA.InboundIP < fwdB.InboundIP
		if isLess {
			return true
		}
		if fwdA.InboundIP != fwdB.InboundIP {
			return false
		}

		return fwdA.InboundPort < fwdB.InboundPort
	})

	return result, nil
}

func (g *NftablesGenerator) WriteStructuredConfig(cfg *nftablesConfig, out io.Writer) error {
	return nftablesTemplate.Execute(out, cfg)
}

func (g *NftablesGenerator) GenerateConfig(m *model.LoadBalancer, out io.Writer) error {
	scfg, err := g.GenerateStructuredConfig(m)
	if err != nil {
		return err
	}
	return g.WriteStructuredConfig(scfg, out)
}
