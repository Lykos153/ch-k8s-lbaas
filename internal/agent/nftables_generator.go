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
		{{- range $dest := $cfg.PolicyAssignments }}
		{{- range $pol := $dest.NetworkPolicies }}
		{{- if eq ((index $cfg.NetworkPolicies $pol).Ports | len) 0 }}
		ct mark {{ $cfg.FWMarkBits | printf "0x%x" }} and {{ $cfg.FWMarkMask | printf "0x%x" }} ip daddr {{ $dest.Address }} jump {{ $pol }};
		{{- else }}
		{{- range $port := (index $cfg.NetworkPolicies $pol).Ports }}
		ct mark {{ $cfg.FWMarkBits | printf "0x%x" }} and {{ $cfg.FWMarkMask | printf "0x%x" }} ip daddr {{ $dest.Address }} {{ $port.Protocol }} {{- if $port.Port }} dport {{ $port.Port -}} {{- if $port.EndPort -}} - {{- $port.EndPort -}} {{- end -}} {{- end }} jump {{ $pol }};
		{{- end }}
		{{- end }}
		{{- end }}
		{{- end }}
		ct mark {{ $cfg.NPMarkBits | printf "0x%x" }} or {{ $cfg.FWMarkBits | printf "0x%x" }} drop;
		ct mark {{ $cfg.FWMarkBits | printf "0x%x" }} and {{ $cfg.FWMarkMask | printf "0x%x" }} accept;
	}

	{{- range $policy := $cfg.NetworkPolicies }}
	chain {{ $policy.Name }} {
		mark set {{ $cfg.NPMarkBits | printf "0x%x" }} or {{ $cfg.FWMarkBits | printf "0x%x" }} ct mark set meta mark
	{{- range $index, $ipblock := $policy.AllowedIPBlocks }}
		ip saddr {{ $ipblock.Cidr }} {{ if eq ($ipblock.Except | len) 0 -}} accept {{- else -}} jump {{ $policy.Name }}-cidr{{ $index -}} {{- end }};
	{{- end }}
		return;
	}
	{{- range $index, $ipblock := $policy.AllowedIPBlocks }}
	{{- if ne ($ipblock.Except | len) 0 }}
	chain {{ $policy.Name }}-cidr{{ $index }} {
	{{- range $except := $ipblock.Except }}
		ip saddr {{ $except }} return;
	{{- end }}
		accept;
	}
	{{- end }}
	{{- end }}
	{{- end }}
}

table ip {{ .NATTableName }} {
	chain {{ .NATPreroutingChainName }} {
{{- range $fwd := .Forwards }}
{{- if ne ($fwd.DestinationAddresses | len) 0 }}
		ip daddr {{ $fwd.InboundIP }} {{ $fwd.Protocol }} dport {{ $fwd.InboundPort }} mark set {{ $cfg.FWMarkBits | printf "0x%x" }} and {{ $cfg.FWMarkMask | printf "0x%x" }} ct mark set meta mark dnat to numgen inc mod {{ $fwd.DestinationAddresses | len }} map {
{{- range $index, $daddr := $fwd.DestinationAddresses }}{{ $index }} : {{ $daddr }}, {{ end -}}
		} : {{ $fwd.DestinationPort }};
{{- end }}
{{- end }}
	}

	chain {{ .NATPostroutingChainName }} {
		mark {{ $cfg.FWMarkBits | printf "0x%x" }} and {{ $cfg.FWMarkMask | printf "0x%x" }} masquerade;
	}
}
`))

	ErrProtocolNotSupported = fmt.Errorf("Protocol is not supported")
)

type allowedIPBlock struct {
	Cidr   string
	Except []string
}

type policyPort struct {
	Protocol string
	Port     *int32
	EndPort  *int32
}

type networkPolicy struct {
	Name            string
	AllowedIPBlocks []allowedIPBlock
	Ports           []policyPort
}

type policyAssignment struct {
	Address         string
	NetworkPolicies []string
}

type nftablesForward struct {
	Protocol             string
	InboundIP            string
	InboundPort          int32
	DestinationAddresses []string
	DestinationPort      int32
}

type nftablesConfig struct {
	FilterTableType         string
	FilterTableName         string
	FilterForwardChainName  string
	NATTableName            string
	NATPostroutingChainName string
	NATPreroutingChainName  string
	FWMarkBits              uint32
	FWMarkMask              uint32
	NPMarkBits              uint32
	Forwards                []nftablesForward
	NetworkPolicies         map[string]networkPolicy
	PolicyAssignments       []policyAssignment
}

type NftablesGenerator struct {
	Cfg config.Nftables
}

func copyAddresses(in []string) []string {
	result := make([]string, len(in))
	copy(result, in)
	return result
}

func copyIPBlocks(in []model.AllowedIPBlock) []allowedIPBlock {
	result := make([]allowedIPBlock, len(in))
	for i, block := range in {
		result[i].Cidr = block.Cidr
		result[i].Except = copyAddresses(block.Except)
	}
	return result
}

func copyPolicyPorts(in []model.PolicyPort) ([]policyPort, error) {
	result := make([]policyPort, len(in))
	var err error
	for i, port := range in {
		result[i].Protocol, err = mapProtocol(port.Protocol)
		if err != nil {
			return nil, err
		}
		result[i].Port = port.Port
		result[i].EndPort = port.EndPort
	}
	return result, nil
}

func copyNetworkPolicies(in []model.NetworkPolicy) ([]networkPolicy, error) {
	result := make([]networkPolicy, len(in))
	var err error
	for i, policy := range in {
		result[i].Name = policy.Name
		result[i].AllowedIPBlocks = copyIPBlocks(policy.AllowedIPBlocks)
		result[i].Ports, err = copyPolicyPorts(policy.Ports)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func copyPolicyAssignment(in []model.PolicyAssignment) []policyAssignment {
	result := make([]policyAssignment, len(in))
	for i, assignment := range in {
		result[i].Address = assignment.Address
		result[i].NetworkPolicies = copyAddresses(assignment.NetworkPolicies)
	}
	return result
}

// Maps from k8s.io/api/core/v1.Protocol objects to strings understood by nftables
func mapProtocol(k8sproto corev1.Protocol) (string, error) {
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
		FWMarkBits:              g.Cfg.FWMarkBits,
		FWMarkMask:              g.Cfg.FWMarkMask,
		NPMarkBits:              g.Cfg.NPMarkBits,
		Forwards:                []nftablesForward{},
		NetworkPolicies:         map[string]networkPolicy{},
		PolicyAssignments:       []policyAssignment{},
	}

	for _, ingress := range m.Ingress {
		for _, port := range ingress.Ports {
			mappedProtocol, err := mapProtocol(port.Protocol)
			if err != nil {
				return nil, err
			}

			addrs := copyAddresses(port.DestinationAddresses)
			sort.Strings(addrs)

			result.Forwards = append(result.Forwards, nftablesForward{
				Protocol:             mappedProtocol,
				InboundIP:            ingress.Address,
				InboundPort:          port.InboundPort,
				DestinationAddresses: addrs,
				DestinationPort:      port.DestinationPort,
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

	result.PolicyAssignments = copyPolicyAssignment(m.PolicyAssignments)
	policies, err := copyNetworkPolicies(m.NetworkPolicies)
	if err != nil {
		return nil, err
	}
	for _, policy := range policies {
		result.NetworkPolicies[policy.Name] = policy
	}

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
