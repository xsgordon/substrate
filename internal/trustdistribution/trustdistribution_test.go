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

package trustdistribution

import (
	"context"
	"strings"
	"testing"

	"go.ate.dev/substrate/internal/clustertrustbundle"
	certsv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

func TestBundleNameForCTB(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"podidentity.podcert.ate.dev:identity:primary-bundle", "podidentity.podcert.ate.dev-identity-primary-bundle"},
		{"plain", "plain"},
	} {
		if got := BundleNameForCTB(tc.in); got != tc.want {
			t.Errorf("BundleNameForCTB(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBundleForCTB(t *testing.T) {
	ctb := &certsv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: "a.podcert.ate.dev:identity:primary-bundle", Labels: map[string]string{"k": "v"}},
		Spec:       certsv1.ClusterTrustBundleSpec{TrustBundle: "-----BEGIN CERTIFICATE-----"},
	}
	b := BundleForCTB(ctb)
	if b.Name != "a.podcert.ate.dev-identity-primary-bundle" {
		t.Errorf("name = %q", b.Name)
	}
	if b.Annotations[originAnnotation] != ctb.Name {
		t.Errorf("origin annotation = %v", b.Annotations)
	}
	if len(b.Spec.Sources) != 1 || b.Spec.Sources[0].InLine != ctb.Spec.TrustBundle {
		t.Errorf("sources = %+v, want the PEM inLine", b.Spec.Sources)
	}
	target := b.Spec.Target.ConfigMap
	if target == nil || target.Key != TargetKey {
		t.Errorf("target = %+v, want a ConfigMap with key %q", target, TargetKey)
	}
	sel := b.Spec.Target.NamespaceSelector
	if sel == nil || len(sel.MatchExpressions) != 1 || sel.MatchExpressions[0].Key != "kubernetes.io/metadata.name" {
		t.Errorf("namespace selector = %+v, want an exists match on kubernetes.io/metadata.name", sel)
	}
	if b.Labels["k"] != "v" {
		t.Errorf("labels = %v, want the CTB's carried over", b.Labels)
	}
}

func TestDetect(t *testing.T) {
	for _, tc := range []struct {
		name      string
		resources []*metav1.APIResourceList
		want      Mode
		wantErr   string
	}{
		{
			name: "clustertrustbundle v1",
			resources: []*metav1.APIResourceList{{GroupVersion: "certificates.k8s.io/v1",
				APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}}}},
			want: ModeClusterTrustBundle,
		},
		{
			name: "trust-manager bundles",
			resources: []*metav1.APIResourceList{{GroupVersion: "trust.cert-manager.io/v1alpha1",
				APIResources: []metav1.APIResource{{Name: "bundles"}}}},
			want: ModeTrustManager,
		},
		{
			name:      "neither",
			resources: []*metav1.APIResourceList{},
			wantErr:   "neither the ClusterTrustBundle API",
		},
		{
			name: "group without the bundles resource",
			resources: []*metav1.APIResourceList{{GroupVersion: "trust.cert-manager.io/v1alpha1",
				APIResources: []metav1.APIResource{{Name: "somethingelse"}}}},
			wantErr: "neither the ClusterTrustBundle API",
		},
		{
			name: "both, clustertrustbundle wins",
			resources: []*metav1.APIResourceList{
				{GroupVersion: "certificates.k8s.io/v1beta1", APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}}},
				{GroupVersion: "trust.cert-manager.io/v1alpha1", APIResources: []metav1.APIResource{{Name: "bundles"}}},
			},
			want: ModeClusterTrustBundle,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kc := kubefake.NewSimpleClientset()
			kc.Resources = tc.resources
			mode, err := Detect(kc.Discovery())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode != tc.want {
				t.Errorf("mode = %q, want %q", mode, tc.want)
			}
		})
	}
}

// dynamicClient builds a fake dynamic client that knows the Bundle kind.
func dynamicClient(t *testing.T, objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	t.Helper()
	scheme := runtime.NewScheme()
	listGVR := BundleGVR.GroupVersion().WithResource("bundles")
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{listGVR: "BundleList"}, objects...)
	return client
}

func ctb(name, pem string, labels map[string]string) *certsv1.ClusterTrustBundle {
	return &certsv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec:       certsv1.ClusterTrustBundleSpec{TrustBundle: pem},
	}
}

func TestTrustManagerPublisher(t *testing.T) {
	ctx := context.Background()
	want := ctb("podidentity.podcert.ate.dev:identity:primary-bundle", "root-a", map[string]string{"k": "v"})

	t.Run("create", func(t *testing.T) {
		dyn := dynamicClient(t)
		p := &TrustManagerPublisher{dyn: dyn}
		if err := p.Ensure(ctx, []*certsv1.ClusterTrustBundle{want}); err != nil {
			t.Fatal(err)
		}
		got, err := dyn.Resource(BundleGVR).Get(ctx, BundleNameForCTB(want.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got.GetAnnotations()[originAnnotation] != want.Name {
			t.Errorf("origin annotation = %v", got.GetAnnotations())
		}
	})

	t.Run("update stale", func(t *testing.T) {
		dyn := dynamicClient(t)
		p := &TrustManagerPublisher{dyn: dyn}
		if err := p.Ensure(ctx, []*certsv1.ClusterTrustBundle{want}); err != nil {
			t.Fatal(err)
		}
		stale := ctb(want.Name, "root-old", nil)
		if err := p.Ensure(ctx, []*certsv1.ClusterTrustBundle{stale}); err != nil {
			t.Fatal(err)
		}
		got, err := dyn.Resource(BundleGVR).Get(ctx, BundleNameForCTB(want.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var spec BundleSpec
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(got.Object["spec"].(map[string]any), &spec); err != nil {
			t.Fatal(err)
		}
		if spec.Sources[0].InLine != "root-old" {
			t.Errorf("inLine = %q, want the updated PEM", spec.Sources[0].InLine)
		}
	})

	t.Run("idempotent", func(t *testing.T) {
		dyn := dynamicClient(t)
		p := &TrustManagerPublisher{dyn: dyn}
		if err := p.Ensure(ctx, []*certsv1.ClusterTrustBundle{want}); err != nil {
			t.Fatal(err)
		}
		dyn.ClearActions()
		if err := p.Ensure(ctx, []*certsv1.ClusterTrustBundle{want}); err != nil {
			t.Fatal(err)
		}
		for _, a := range dyn.Actions() {
			if v := a.GetVerb(); v == "create" || v == "update" {
				t.Errorf("verb %s on an already-correct bundle", v)
			}
		}
	})
}

func TestCTBPublisher(t *testing.T) {
	ctx := context.Background()
	want := ctb("podidentity.podcert.ate.dev:identity:primary-bundle", "root-a", map[string]string{"k": "v"})

	for _, tc := range []struct {
		name     string
		existing *certsv1.ClusterTrustBundle
		wantVerb string
	}{
		{name: "missing", wantVerb: "create"},
		{name: "matching", existing: ctb(want.Name, "root-a", map[string]string{"k": "v"})},
		{name: "stale bundle", existing: ctb(want.Name, "root-old", map[string]string{"k": "v"}), wantVerb: "update"},
		{name: "stale labels", existing: ctb(want.Name, "root-a", nil), wantVerb: "update"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kc := kubefake.NewSimpleClientset()
			kc.Resources = []*metav1.APIResourceList{{
				GroupVersion: certsv1.SchemeGroupVersion.String(),
				APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}},
			}}
			client, err := clustertrustbundle.NewClient(kc, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.existing != nil {
				if _, err := client.Create(ctx, tc.existing, metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			kc.ClearActions()

			p := &CTBPublisher{client: client}
			if err := p.Ensure(ctx, []*certsv1.ClusterTrustBundle{want}); err != nil {
				t.Fatal(err)
			}

			var writes []string
			for _, a := range kc.Actions() {
				if v := a.GetVerb(); v == "create" || v == "update" {
					writes = append(writes, v)
				}
			}
			if tc.wantVerb == "" && len(writes) != 0 {
				t.Errorf("writes = %v, want none", writes)
			}
			if tc.wantVerb != "" && (len(writes) != 1 || writes[0] != tc.wantVerb) {
				t.Errorf("writes = %v, want [%s]", writes, tc.wantVerb)
			}
			got, err := client.Get(ctx, want.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got.Spec != want.Spec || got.Labels["k"] != "v" {
				t.Errorf("stored = %+v, want spec %+v with label k=v", got.Spec, want.Spec)
			}
		})
	}
}
