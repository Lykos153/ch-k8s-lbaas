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
package model

import (
	"fmt"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
)

// TODO: clean this up. Does it make sense anyway to have NetworkPolicy alongside Service here?
// var (
// 	ErrNotAValidKey = errors.New("Not a valid namespace/name key")
// )

type NetworkPolicyIdentifier struct {
	Namespace string
	Name      string
}

func FromNetworkPolicy(pol *networkingv1.NetworkPolicy) NetworkPolicyIdentifier {
	return NetworkPolicyIdentifier{Namespace: pol.Namespace, Name: pol.Name}
}

func PolicyFromObject(obj interface{}) (NetworkPolicyIdentifier, error) {
	info, err := meta.Accessor(obj)
	if err != nil {
		return NetworkPolicyIdentifier{}, err
	}
	return NetworkPolicyIdentifier{Namespace: info.GetNamespace(), Name: info.GetName()}, nil
}

func PolicyFromKey(key string) (NetworkPolicyIdentifier, error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 {
		return NetworkPolicyIdentifier{}, ErrNotAValidKey
	}
	return NetworkPolicyIdentifier{Namespace: parts[0], Name: parts[1]}, nil
}

func (id NetworkPolicyIdentifier) ToKey() string {
	return fmt.Sprintf("%s/%s", id.Namespace, id.Name)
}
