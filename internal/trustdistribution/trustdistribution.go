// Copyright 2026 The Agent Substrate Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package trustdistribution publishes the podcert trust anchors. The
// ClusterTrustBundle API is the native path. A cluster that does not serve it
// publishes the same PEM through a trust-manager Bundle instead, which syncs
// a ConfigMap carrying the bundle into namespaces. OpenShift is the concrete
// case today: its FeatureGate mechanism cannot set the --runtime-config the
// beta certificates.k8s.io APIs need (see docs/dev/kata-sandbox-spike.md for
// the field notes), so the ClusterTrustBundle path is unavailable there and
// the cert-manager ecosystem's trust-manager is Red Hat's direction for trust
// distribution.
//
// A cluster that serves neither path is an error, not a silent skip: nothing
// downstream can verify a peer without the anchors.
//
// This covers trust distribution only. Issuance still runs through
// PodCertificateRequests, which the same beta API group gates; a cluster
// without that API cannot run the signers at all, whatever this package
// publishes.
package trustdistribution

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.ate.dev/substrate/internal/clustertrustbundle"
	certsv1 "k8s.io/api/certificates/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Mode is the publication path a cluster supports.
type Mode string

const (
	// ModeClusterTrustBundle publishes through the ClusterTrustBundle API.
	ModeClusterTrustBundle Mode = "clustertrustbundle"
	// ModeTrustManager publishes through a trust-manager Bundle, which
	// syncs a ConfigMap carrying the anchors into namespaces.
	ModeTrustManager Mode = "trust-manager"
)

// BundleGroupVersion is the trust-manager API this package speaks. Local
// types below stand in for the trust-manager Go module, so it stays out of
// the vendor tree for the sake of one CRD.
var BundleGroupVersion = schema.GroupVersion{Group: "trust.cert-manager.io", Version: "v1alpha1"}

// BundleGVR is the bundles resource of that group.
var BundleGVR = BundleGroupVersion.WithResource("bundles")

// TargetKey is the key the synced ConfigMaps carry the PEM under. It matches
// the trust-bundle.pem naming the component volumes use.
const TargetKey = "trust-bundle.pem"

// originAnnotation records the ClusterTrustBundle name a Bundle stands in
// for, so the mapping survives inspection from either side.
const originAnnotation = "ate.dev/cluster-trust-bundle"

// Detect reports which publication path the cluster serves. The
// ClusterTrustBundle API wins when both exist: it is the native one, and the
// consumers project it without trust-manager in the path.
func Detect(d discovery.DiscoveryInterface) (Mode, error) {
	_, err := clustertrustbundle.Discover(d)
	switch {
	case err == nil:
		return ModeClusterTrustBundle, nil
	case errors.Is(err, clustertrustbundle.ErrNotServed):
	default:
		return "", fmt.Errorf("while discovering the ClusterTrustBundle API: %w", err)
	}
	resources, err := d.ServerResourcesForGroupVersion(BundleGroupVersion.String())
	if err != nil && !apierrors.IsNotFound(err) {
		return "", fmt.Errorf("while discovering the trust-manager Bundle API: %w", err)
	}
	if err == nil {
		for _, r := range resources.APIResources {
			if r.Name == "bundles" {
				return ModeTrustManager, nil
			}
		}
	}
	return "", fmt.Errorf("this cluster serves neither the ClusterTrustBundle API (certificates.k8s.io v1 or v1beta1) nor the trust-manager Bundle API (trust.cert-manager.io/v1alpha1); enable the beta certificates.k8s.io APIs, or install trust-manager, before deploying the podcertificate controller")
}

// BundleNameForCTB maps a ClusterTrustBundle name to the name of the
// trust-manager Bundle, and of the ConfigMap trust-manager syncs from it.
// Colons are legal in ClusterTrustBundle names and not in object names.
func BundleNameForCTB(name string) string {
	return strings.ReplaceAll(name, ":", "-")
}

// Publisher delivers the signer trust anchors that components and pods
// verify peer certificates against.
type Publisher interface {
	// Ensure makes the desired bundles exist with exactly this content,
	// creating or updating as needed. It is idempotent.
	Ensure(ctx context.Context, want []*certsv1.ClusterTrustBundle) error
}

// New returns the publisher the cluster supports, and the mode it picked.
func New(kc kubernetes.Interface, dyn dynamic.Interface) (Publisher, Mode, error) {
	mode, err := Detect(kc.Discovery())
	if err != nil {
		return nil, "", err
	}
	switch mode {
	case ModeClusterTrustBundle:
		client, err := clustertrustbundle.NewClient(kc, nil)
		if err != nil {
			return nil, "", err
		}
		return &CTBPublisher{client: client}, mode, nil
	case ModeTrustManager:
		return &TrustManagerPublisher{dyn: dyn}, mode, nil
	}
	return nil, "", fmt.Errorf("unknown trust distribution mode %q", mode)
}

// CTBPublisher publishes through the ClusterTrustBundle API.
type CTBPublisher struct {
	client *clustertrustbundle.Client
}

// Ensure creates or updates each bundle through the ClusterTrustBundle API.
func (p *CTBPublisher) Ensure(ctx context.Context, want []*certsv1.ClusterTrustBundle) error {
	for _, w := range want {
		ctb, err := p.client.Get(ctx, w.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			_, err := p.client.Create(ctx, w, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("while creating ClusterTrustBundle %s: %w", w.Name, err)
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("while getting ClusterTrustBundle %s: %w", w.Name, err)
		}
		if apiequality.Semantic.DeepEqual(w.Labels, ctb.Labels) && apiequality.Semantic.DeepEqual(w.Spec, ctb.Spec) {
			continue
		}
		ctb = ctb.DeepCopy()
		ctb.Labels = w.Labels
		ctb.Spec.TrustBundle = w.Spec.TrustBundle
		if _, err := p.client.Update(ctx, ctb, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("while updating ClusterTrustBundle %s: %w", w.Name, err)
		}
	}
	return nil
}

// TrustManagerPublisher publishes through trust-manager Bundles.
type TrustManagerPublisher struct {
	dyn dynamic.Interface
}

// Bundle is the subset of the trust-manager Bundle CRD this publisher uses:
// one inLine PEM source and a ConfigMap target. The full CRD has more
// source and target types; the local types carry only what is written here,
// and unknown fields in existing objects are left alone.
type Bundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BundleSpec `json:"spec,omitempty"`
}

// BundleSpec is the sources plus the sync target.
type BundleSpec struct {
	Sources []BundleSource `json:"sources"`
	Target  BundleTarget   `json:"target,omitempty"`
}

// BundleSource is one PEM source; inLine carries the PEM directly, which is
// what a controller publishing the anchors itself wants: no source ConfigMap
// in trust-manager's namespace, and rotation is a spec update.
type BundleSource struct {
	InLine string `json:"inLine,omitempty"`
}

// BundleTarget names what trust-manager syncs and where.
type BundleTarget struct {
	ConfigMap         *BundleConfigMapTarget `json:"configMap,omitempty"`
	NamespaceSelector *metav1.LabelSelector  `json:"namespaceSelector,omitempty"`
}

// BundleConfigMapTarget is the synced ConfigMap.
type BundleConfigMapTarget struct {
	Key string `json:"key,omitempty"`
}

// BundleForCTB translates a desired ClusterTrustBundle into the equivalent
// trust-manager Bundle: the same PEM as an inLine source, synced into a
// ConfigMap named after it.
//
// The namespace selector matches the builtin kubernetes.io/metadata.name
// label, which every namespace carries: the explicit form of "every
// namespace". An empty selector means the same today, but the trust-manager
// documentation reserves the right to narrow it to trust-manager's own
// namespace, and the ClusterTrustBundle this stands in for is cluster-scoped.
func BundleForCTB(ctb *certsv1.ClusterTrustBundle) *Bundle {
	b := &Bundle{
		TypeMeta: metav1.TypeMeta{APIVersion: BundleGroupVersion.String(), Kind: "Bundle"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        BundleNameForCTB(ctb.Name),
			Labels:      ctb.Labels,
			Annotations: map[string]string{originAnnotation: ctb.Name},
		},
		Spec: BundleSpec{
			Sources: []BundleSource{{InLine: ctb.Spec.TrustBundle}},
			Target: BundleTarget{
				ConfigMap: &BundleConfigMapTarget{Key: TargetKey},
				NamespaceSelector: &metav1.LabelSelector{
					MatchExpressions: []metav1.LabelSelectorRequirement{{
						Key:      "kubernetes.io/metadata.name",
						Operator: metav1.LabelSelectorOpExists,
					}},
				},
			},
		},
	}
	if len(ctb.Labels) == 0 {
		b.Labels = nil
	}
	return b
}

// Ensure creates or updates the trust-manager Bundle for each desired
// ClusterTrustBundle.
func (p *TrustManagerPublisher) Ensure(ctx context.Context, want []*certsv1.ClusterTrustBundle) error {
	for _, ctb := range want {
		b := BundleForCTB(ctb)
		content, err := runtime.DefaultUnstructuredConverter.ToUnstructured(b)
		if err != nil {
			return fmt.Errorf("while converting Bundle %s: %w", b.Name, err)
		}
		obj := &unstructured.Unstructured{Object: content}
		existing, err := p.dyn.Resource(BundleGVR).Get(ctx, b.Name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			if _, err := p.dyn.Resource(BundleGVR).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("while creating trust-manager Bundle %s: %w", b.Name, err)
			}
			continue
		case err != nil:
			return fmt.Errorf("while getting trust-manager Bundle %s: %w", b.Name, err)
		}
		if apiequality.Semantic.DeepEqual(existing.Object["spec"], obj.Object["spec"]) &&
			apiequality.Semantic.DeepEqual(existing.GetLabels(), b.Labels) {
			continue
		}
		// The server rejects an update without the current resourceVersion.
		obj.SetResourceVersion(existing.GetResourceVersion())
		if _, err := p.dyn.Resource(BundleGVR).Update(ctx, obj, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("while updating trust-manager Bundle %s: %w", b.Name, err)
		}
	}
	return nil
}
