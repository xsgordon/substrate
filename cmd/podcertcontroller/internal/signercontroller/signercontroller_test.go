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

package signercontroller

import (
	"context"
	"testing"

	"go.ate.dev/substrate/internal/trustdistribution"
	certsv1 "k8s.io/api/certificates/v1"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeSigner struct {
	bundles []*certsv1.ClusterTrustBundle
}

func (fakeSigner) SignerName() string { return "example.com/signer" }

func (f fakeSigner) DesiredClusterTrustBundles() ([]*certsv1.ClusterTrustBundle, error) {
	return f.bundles, nil
}

func (fakeSigner) MakeCert(context.Context, *certsv1beta1.PodCertificateRequest) error {
	return nil
}

type assignedHasher struct{}

func (assignedHasher) AssignedToThisReplica(context.Context, string) bool { return true }

type deniedHasher struct{}

func (deniedHasher) AssignedToThisReplica(context.Context, string) bool { return false }

// recordingPublisher records what ensureBundles asked it to publish. The
// publication mechanics themselves are covered in the trustdistribution
// package's tests.
type recordingPublisher struct {
	got []*certsv1.ClusterTrustBundle
}

func (p *recordingPublisher) Ensure(_ context.Context, want []*certsv1.ClusterTrustBundle) error {
	p.got = want
	return nil
}

func bundle(trust string, labels map[string]string) *certsv1.ClusterTrustBundle {
	return &certsv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: "example.com:signer:bundle", Labels: labels},
		Spec:       certsv1.ClusterTrustBundleSpec{SignerName: "example.com/signer", TrustBundle: trust},
	}
}

func TestEnsureBundlesPublishes(t *testing.T) {
	want := []*certsv1.ClusterTrustBundle{bundle("root-a", map[string]string{"k": "v"})}
	pub := &recordingPublisher{}
	c := &Controller{publish: pub, hasher: assignedHasher{}, handler: fakeSigner{bundles: want}}
	c.ensureBundles(context.Background())
	if len(pub.got) != 1 || pub.got[0].Spec.TrustBundle != "root-a" {
		t.Errorf("published = %+v, want the signer's desired bundle", pub.got)
	}
}

// Only the replica the rendezvous hasher assigns maintains the bundles, so
// two replicas do not fight over the same objects.
func TestEnsureBundlesHonorsSharding(t *testing.T) {
	pub := &recordingPublisher{}
	c := &Controller{publish: pub, hasher: deniedHasher{}, handler: fakeSigner{bundles: []*certsv1.ClusterTrustBundle{bundle("root-a", nil)}}}
	c.ensureBundles(context.Background())
	if len(pub.got) != 0 {
		t.Errorf("published = %+v, want nothing from an unassigned replica", pub.got)
	}
}

var _ trustdistribution.Publisher = (*recordingPublisher)(nil)
