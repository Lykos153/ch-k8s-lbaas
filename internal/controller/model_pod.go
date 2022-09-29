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
package controller

import (
	goerrors "errors"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"

	"k8s.io/klog"

	"github.com/cloudandheat/ch-k8s-lbaas/internal/model"
	"github.com/cloudandheat/ch-k8s-lbaas/internal/openstack"
)

var (
	errPortNotFoundInSubset = goerrors.New("port not found in subset")
)

type PodLoadBalancerModelGenerator struct {
	l3portmanager   openstack.L3PortManager
	services        corelisters.ServiceLister
	networkpolicies networkinglisters.NetworkPolicyLister
	endpoints       corelisters.EndpointsLister
	pods            corelisters.PodLister
}

func NewPodLoadBalancerModelGenerator(
	l3portmanager openstack.L3PortManager,
	services corelisters.ServiceLister,
	endpoints corelisters.EndpointsLister,
	networkpolicies networkinglisters.NetworkPolicyLister,
	pods corelisters.PodLister) *PodLoadBalancerModelGenerator {
	return &PodLoadBalancerModelGenerator{
		l3portmanager:   l3portmanager,
		services:        services,
		endpoints:       endpoints,
		networkpolicies: networkpolicies,
		pods:            pods,
	}
}

func (g *PodLoadBalancerModelGenerator) findPort(subset *corev1.EndpointSubset, name string, targetPort int32, protocol corev1.Protocol) (int32, error) {
	nameMatch := int32(-1)
	portMatch := int32(-1)
	for _, epPort := range subset.Ports {
		if epPort.Protocol != protocol {
			continue
		}
		if name != "" && epPort.Name == name {
			nameMatch = epPort.Port
		}
		if epPort.Port == targetPort {
			portMatch = epPort.Port
		}
	}

	if nameMatch >= 0 {
		return nameMatch, nil
	}
	if portMatch >= 0 {
		return portMatch, nil
	}
	return -1, errPortNotFoundInSubset
}

func containsPort(port int32, proto *corev1.Protocol, portList []networkingv1.NetworkPolicyPort) bool {
	klog.Infof("Looking for port %d proto %#v", port, *proto)
	for _, p := range portList {
		klog.Infof("%#v: port %d proto %#v", p, p.Port.IntVal, p.Protocol)
		if *p.Protocol == *proto &&
			((p.EndPort == nil && p.Port.IntVal == port) ||
				(p.EndPort != nil && p.Port.IntVal <= port && *p.EndPort >= port)) {
			klog.Infof("Found port in %#v", p)
			return true
		}
	}
	return false
}

func buildNetworkPolicy(in *networkingv1.NetworkPolicy) model.NetworkPolicy {
	newPolicy := model.NetworkPolicy{
		Name:            in.Name,
		AllowedIPBlocks: []model.AllowedIPBlock{},
		Ports:           []model.PolicyPort{},
	}
	for _, ingress := range in.Spec.Ingress {
		klog.Infof("Processing ingress %#v", ingress)
		for _, port := range ingress.Ports {
			newPort := model.PolicyPort{
				Protocol: *port.Protocol,
				EndPort:  port.EndPort,
			}
			if port.Port != nil {
				newPort.Port = &port.Port.IntVal
			}
			klog.Infof("Adding proto %s port %d to %d",
				newPort.Protocol, newPort.Port, newPort.EndPort)
			newPolicy.Ports = append(newPolicy.Ports, newPort)
		}
		for _, from := range ingress.From {
			if from.IPBlock == nil {
				continue
			}
			newBlock := model.AllowedIPBlock{
				Cidr: from.IPBlock.CIDR,
			}
			for _, except := range from.IPBlock.Except {
				newBlock.Except = append(newBlock.Except, except)
			}
			klog.Infof("Adding block %s with %d excepts",
				newBlock.Cidr, len(newBlock.Except))
			newPolicy.AllowedIPBlocks = append(newPolicy.AllowedIPBlocks, newBlock)
		}
	}
	return newPolicy
}

func (g *PodLoadBalancerModelGenerator) GenerateModel(portAssignment map[string]string) (*model.LoadBalancer, error) {
	result := &model.LoadBalancer{}

	allPolicies, err := g.networkpolicies.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	networkPolicies := make([]model.NetworkPolicy, 0, len(allPolicies))
	policyMap := map[string][]string{} // dest addr => ingress ipBlock
	for _, pol := range allPolicies {
		klog.Infof("Processing policy %s", pol.Name)
		if len(pol.Spec.Ingress) == 0 {
			klog.Infof("Skipping because policy has no ingress rule")
			continue
		}

		networkPolicies = append(networkPolicies, buildNetworkPolicy(pol))

		// build policyMap
		selector, err := metav1.LabelSelectorAsSelector(&pol.Spec.PodSelector)
		if err != nil {
			return nil, err
		}

		pods, err := g.pods.Pods(pol.Namespace).List(selector)
		if err != nil {
			return nil, err
		}
		for _, pod := range pods {
			for _, addr := range pod.Status.PodIPs {
				klog.Infof("Adding policy %s to address %s", pol.Name, addr.IP)
				policyMap[addr.IP] = append(policyMap[addr.IP], pol.Name)
			}
		}
	}
	klog.Infof("Done getting %d policies applying to %d addresses", len(allPolicies), len(policyMap))

	ingressMap := map[string]model.IngressIP{}

	for serviceKey, portID := range portAssignment {
		id, _ := model.FromKey(serviceKey)
		svc, err := g.services.Services(id.Namespace).Get(id.Name)
		if err != nil {
			return nil, err
		}

		ep, err := g.endpoints.Endpoints(id.Namespace).Get(id.Name)
		if err != nil {
			// no endpoints exist or are not retrievable -> we ignore that for
			// now because this may happen during bootstrapping of a service
			continue
		}
		if len(ep.Subsets) < 1 {
			// no point in doing anything with the service here
			continue
		}
		// TODO: handle multiple subsets. This is tricky because our model
		// currently does not support different ports per destination IP.
		epSubset := ep.Subsets[0]
		if len(ep.Subsets) > 1 {
			klog.Warningf(
				"LB model for service %s will be inaccurate: more than one subset",
				serviceKey,
			)
		}

		ingress, ok := ingressMap[portID]
		if !ok {
			klog.Infof("Calling GetInternalAddress for portID=%q, serviceKey=%q", portID, serviceKey)
			ingressIP, err := g.l3portmanager.GetInternalAddress(portID)
			if err != nil {
				return nil, err
			}
			ingress = model.IngressIP{
				Address: ingressIP,
				Ports:   []model.PortForward{},
			}
		}

		for _, svcPort := range svc.Spec.Ports {
			targetPort := int32(svcPort.TargetPort.IntValue())
			portName := svcPort.Name
			if targetPort == 0 {
				targetPort = svcPort.Port
				portName = svcPort.TargetPort.String()
			}
			destinationPort, err := g.findPort(
				&epSubset,
				portName, targetPort, svcPort.Protocol,
			)
			if err != nil {
				klog.Warningf(
					"LB model for service %s is inaccurate: failed to find matching Endpoints for Service Port %#v",
					serviceKey,
					svcPort,
				)
				continue
			}

			addresses := make([]string, len(epSubset.Addresses))
			for i, addr := range epSubset.Addresses {
				addresses[i] = addr.IP
			}

			ingress.Ports = append(ingress.Ports, model.PortForward{
				Protocol:             svcPort.Protocol,
				InboundPort:          svcPort.Port,
				DestinationPort:      destinationPort,
				DestinationAddresses: addresses,
			})
		}

		ingressMap[portID] = ingress
	}

	result.Ingress = make([]model.IngressIP, len(ingressMap))
	i := 0
	for _, ingress := range ingressMap {
		result.Ingress[i] = ingress
		i++
	}
	result.NetworkPolicies = networkPolicies
	result.PolicyAssignments = make([]model.PolicyAssignment, len(policyMap))
	i = 0
	for addr, policies := range policyMap {
		result.PolicyAssignments[i].Address = addr
		result.PolicyAssignments[i].NetworkPolicies = policies
		i++
	}

	return result, nil
}
