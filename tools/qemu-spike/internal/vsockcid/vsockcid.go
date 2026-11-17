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

// Package vsockcid hands out vhost-vsock guest CIDs. Unlike Cloud
// Hypervisor's hybrid-vsock, where the host reaches the guest through a
// per-VM unix socket, QEMU's vhost-vsock shares one host-wide CID space, so
// each sandbox needs a CID that is unique on the node.
//
// The allocation is stable: the CID is a hash of the sandbox name, so a VM
// restores onto the same CID it snapshotted with (migrating vhost-vsock
// requires the guest-cid to match on both ends). A hash collision moves to
// the next free CID by linear probing.
package vsockcid

import (
	"hash/fnv"
	"sync"
)

// Reserved CIDs: 0 is the hypervisor, 1 is local communication, 2 is the
// host. VMADDR_CID_ANY is 0xffffffff.
const (
	minCID = 0x10000
	maxCID = 0xffff0000
)

// Allocator tracks CIDs handed out in this process. A production allocator
// persists assignments per node and probes collisions by attaching the
// vhost-vsock device; QEMU rejects a guest-cid another VM holds.
type Allocator struct {
	mu      sync.Mutex
	claimed map[uint32]string
}

// New returns an empty allocator.
func New() *Allocator {
	return &Allocator{claimed: make(map[uint32]string)}
}

// Allocate returns the stable CID for name, or the next free one when that
// CID is taken by another name.
func (a *Allocator) Allocate(name string) uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	cid := stable(name)
	for {
		owner, ok := a.claimed[cid]
		if !ok {
			a.claimed[cid] = name
			return cid
		}
		if owner == name {
			return cid
		}
		cid++
	}
}

// Release forgets the CID held by name.
func (a *Allocator) Release(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for cid, owner := range a.claimed {
		if owner == name {
			delete(a.claimed, cid)
		}
	}
}

// stable maps a name into the allocatable CID range.
func stable(name string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(name))
	return minCID + h.Sum32()%(maxCID-minCID)
}
