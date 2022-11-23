/*
Copyright The CloudNativePG Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"regexp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strconv"
)

// This variable stores the result of the DetectSecurityContextConstraints check
var haveSCC bool

// This variable specifies whether we should set the SeccompProfile or not in the pods
var supportSeccomp bool

// This variable store the result of DetectIstioSupport
var haveIstio bool

// `minorVersionRegexp` is used to extract the minor version from
// the Kubernetes API server version. Some providers, like AWS,
// append a "+" to the Kubernetes minor version to presumably
// indicate that some maintenance patches have been back-ported
// beyond the standard end-of-life of the release.
var minorVersionRegexp = regexp.MustCompile(`^([0-9]+)\+?$`)

// GetDiscoveryClient creates a discovery client or return error
func GetDiscoveryClient() (*discovery.DiscoveryClient, error) {
	config, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, err
	}

	return discoveryClient, nil
}

func resourceExist(client *discovery.DiscoveryClient, groupVersion, kind string) (bool, error) {
	apiResourceList, err := client.ServerResourcesForGroupVersion(groupVersion)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}

		return false, err
	}

	for _, resource := range apiResourceList.APIResources {
		if resource.Name == kind {
			return true, nil
		}
	}

	return false, nil
}

// DetectSecurityContextConstraints connects to the discovery API and find out if
// we're running under a system that implements OpenShift Security Context Constraints
func DetectSecurityContextConstraints(client *discovery.DiscoveryClient) (err error) {
	haveSCC, err = resourceExist(client, "security.openshift.io/v1", "securitycontextconstraints")
	if err != nil {
		return err
	}

	return nil
}

// HaveSecurityContextConstraints returns true if we're running under a system that implements
// OpenShift Security Context Constraints
// It panics if called before DetectSecurityContextConstraints
func HaveSecurityContextConstraints() bool {
	return haveSCC
}

// PodMonitorExist tries to find the PodMonitor resource in the current cluster
func PodMonitorExist(client *discovery.DiscoveryClient) (bool, error) {
	exist, err := resourceExist(client, "monitoring.coreos.com/v1", "podmonitors")
	if err != nil {
		return false, err
	}

	return exist, nil
}

// HaveSeccompSupport returns true if Seccomp is supported. If it is, we should
// set the SeccompProfile in the pods
func HaveSeccompSupport() bool {
	return supportSeccomp
}

// extractK8sMinorVersion extracts and parses the Kubernetes minor version from
// the version info that's been  detected by discovery client
func extractK8sMinorVersion(info *version.Info) (int, error) {
	matches := minorVersionRegexp.FindStringSubmatch(info.Minor)
	if matches == nil {
		// we couldn't detect the minor version of Kubernetes
		return 0, fmt.Errorf("invalid Kubernetes minor version: %s", info.Minor)
	}

	return strconv.Atoi(matches[1])
}

// DetectSeccompSupport checks the version of Kubernetes in the cluster to determine
// whether Seccomp is supported
func DetectSeccompSupport(client *discovery.DiscoveryClient) (err error) {
	supportSeccomp = false
	kubernetesVersion, err := client.ServerVersion()
	if err != nil {
		return err
	}

	minor, err := extractK8sMinorVersion(kubernetesVersion)
	if err != nil {
		return err
	}

	if minor >= 24 {
		supportSeccomp = true
	}

	return
}

// DetectIstioSupport will detect if the Istio api group exists in the current
// Kubernetes cluster and if the resource SideCar exists.
func DetectIstioSupport(client *discovery.DiscoveryClient) (err error) {
	haveIstio = false
	haveIstio, err = resourceExist(client, "networking.istio.io/v1beta1", "sidecar")
	if err != nil {
		return err
	}

	return nil
}

// HaveIstio returns true if this cluster has Istio deployed
// Even having Istio deployed doesn't mean that Istio will do something to the cluster
// That's why we need to also check if the namespace is labeled
func HaveIstio() bool {
	return haveIstio
}

// DetectIstioInNamespace will return true and no error in case the `namespace`
// has the label "istio-injection=enabled"
func DetectIstioInNamespace(ctx context.Context, namespace string) (bool, error) {
	config := ctrl.GetConfigOrDie()
	kubeInterface := kubernetes.NewForConfigOrDie(config)
	namespaceObject, err := kubeInterface.CoreV1().Namespaces().Get(ctx, namespace, v1.GetOptions{})
	if err != nil {
		return false, err
	}

	if value, ok := namespaceObject.Labels["istio-injection"]; ok && value == "enabled" {
		return true, nil
	}

	return false, nil
}

func IsIstioIgnoringPod(ctx context.Context, kubeClient client.Client, namespace, podName string) (bool, error) {
	var pod corev1.Pod
	if err := kubeClient.Get(ctx, client.ObjectKey{Name: podName, Namespace: namespace}, &pod); err != nil {
		return false, err
	}
	labels := pod.Labels

	if value, ok := labels["sidecar.istio.io/injec"]; ok && value == "false" {
		return true, nil
	}

	return false, nil
}
