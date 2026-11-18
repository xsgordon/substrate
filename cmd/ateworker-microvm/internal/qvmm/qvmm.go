//go:build linux

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

// Package qvmm drives a QEMU micro-VM over QMP, the second VMM backend of
// the microvm sandbox class (selected by a SandboxConfig version whose
// assets name "qemu" instead of "cloud-hypervisor"). The device set is
// fixed on the command line — tap by inherited fd, vhost-vsock,
// vhost-user-fs, the kata guest image on virtio-blk — and guest RAM is a
// shared memory-backend-file, so a snapshot is that file plus a device-state
// migration stream taken with the x-ignore-shared capability, and a restore
// launches a fresh QEMU over a staged copy of the file with -incoming defer.
// The mechanism, and its behavior across repeated suspend and restore
// cycles, is validated in tools/qemu-spike and recorded in
// docs/dev/kata-sandbox-spike.md.
package qvmm

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"go.ate.dev/substrate/cmd/ateworker-microvm/internal/child"
	"go.ate.dev/substrate/cmd/ateworker-microvm/internal/qmp"
	"golang.org/x/sys/unix"
)

// Snapshot file names, in the checkpoint dir next to the tars the microvm
// class already ships and the base-id file.
const (
	// RAMFile is the sparse memory-backend image: the guest's whole RAM.
	RAMFile = "qemu-ram.img"
	// DevstateFile is the migration stream: device state only, taken with
	// x-ignore-shared so RAM never enters it.
	DevstateFile = "qemu-devstate.bin"
	// VcpusFile records the VM's vCPU count, which a MEMORY restore must
	// reproduce exactly (the memory-backend and topology come from it).
	VcpusFile = "qemu-vcpus"
)

// Options configure one QEMU launch. Cold boots set Kernel, Cmdline and
// GuestImage; restores set Incoming and point RAMFile at a staged copy of
// the snapshot's RAMFile. The device set must be identical between the VM a
// snapshot was taken from and the VM it is restored into, which the caller
// guarantees by deriving both from the same options.
type Options struct {
	// Binary is the QEMU executable. It may sit in an extracted asset tree
	// carrying its own dynamic loader and libraries (see loaderPrefix);
	// the SNO deployment stages OSC's qemu-kvm that way.
	Binary string
	// QMPSocket is the unix socket QEMU serves QMP on.
	QMPSocket string
	// MemoryBytes is guest RAM; it must match the size of RAMFile.
	MemoryBytes int64
	// VCPUs is the SMP count.
	VCPUs int
	// Kernel and Cmdline boot the guest (cold boot only; ignored on
	// incoming, where CPU and RAM come from the migration stream).
	Kernel, Cmdline string
	// GuestImage is the kata guest image, attached read-only on virtio-blk.
	GuestImage string
	// RAMFile is the shared memory-backend file. The caller creates it
	// (sparse, MemoryBytes large) for a cold boot, or stages a copy of the
	// snapshot's image for a restore. QEMU maps it read-write: the running
	// guest's writes land in this file, so it is the actor's private
	// working copy, never the snapshot itself.
	RAMFile string
	// VsockCID is the vhost-vsock guest CID (see CIDFor).
	VsockCID uint32
	// FsSocket is the virtiofsd vhost-user socket; FsTag the share's tag.
	FsSocket, FsTag string
	// ConsoleLog receives the guest console (virtio-console, hvc0).
	ConsoleLog string
	// NetMAC is the guest NIC's MAC; NetFile is its tap, passed to QEMU as
	// the child's fd 3. The MAC is fixed across an actor's lineage because
	// a restored guest's ARP cache still holds it.
	NetMAC  string
	NetFile *os.File
	// Incoming launches the VM paused with -incoming defer, for
	// RestoreIncoming.
	Incoming bool
	// Stdout/Stderr receive QEMU's own output.
	Stdout, Stderr io.Writer
	// SysProcAttr, when set, is applied to the QEMU process.
	SysProcAttr *syscall.SysProcAttr
}

// VM is one launched QEMU process and its QMP connection.
type VM struct {
	proc *child.Process
	qmp  *qmp.Conn
}

// Proc returns the QEMU process, for teardown and crash watching.
func (v *VM) Proc() *child.Process { return v.proc }

// QMP returns the QMP connection.
func (v *VM) QMP() *qmp.Conn { return v.qmp }

// Stop closes the QMP connection and kills the process.
func (v *VM) Stop() {
	_ = v.qmp.Close()
	v.proc.Stop()
}

// loaderPrefix returns the argv prefix that runs Binary through a staged
// dynamic loader, when the asset tree carries one next to it. A
// distroless worker image has no glibc of its own, so a distro QEMU must
// bring its loader and libraries; a statically self-sufficient tree (or a
// plain PATH binary) needs no prefix.
func loaderPrefix(binary string) ([]string, error) {
	dir := filepath.Dir(binary)
	for _, name := range []string{"ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1"} {
		loader := filepath.Join(dir, name)
		if fi, err := os.Stat(loader); err == nil && fi.Mode().IsRegular() {
			return []string{loader, "--library-path", filepath.Join(dir, "lib"), binary}, nil
		}
	}
	return []string{binary}, nil
}

// Launch starts QEMU with the options' device set and connects to its QMP
// socket. A cold boot leaves the VM running; an Incoming launch leaves it
// paused, waiting for RestoreIncoming.
func Launch(ctx context.Context, o Options) (*VM, error) {
	if o.Binary == "" || o.QMPSocket == "" || o.RAMFile == "" || o.NetFile == nil {
		return nil, fmt.Errorf("qvmm.Launch requires Binary, QMPSocket, RAMFile and NetFile")
	}
	_ = os.Remove(o.QMPSocket)
	memArg := fmt.Sprintf("%d", o.MemoryBytes)
	args := []string{
		"-enable-kvm", "-cpu", "host",
		"-machine", "q35,memory-backend=mem",
		"-smp", fmt.Sprintf("%d", o.VCPUs),
		"-m", memArg,
		"-object", fmt.Sprintf("memory-backend-file,id=mem,size=%s,mem-path=%s,share=on", memArg, o.RAMFile),
		"-chardev", "file,id=con0,path=" + o.ConsoleLog,
		"-device", "virtio-serial",
		"-device", "virtconsole,chardev=con0",
		"-chardev", "socket,id=fs0,path=" + o.FsSocket,
		"-device", "vhost-user-fs-pci,chardev=fs0,tag=" + o.FsTag,
		"-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d", o.VsockCID),
		"-object", "rng-random,filename=/dev/urandom,id=rng0",
		"-device", "virtio-rng-pci,rng=rng0",
		"-drive", "file=" + o.GuestImage + ",format=raw,if=virtio,readonly=on",
		// fd 3 in the child: the tap, passed through ExtraFiles.
		"-netdev", "tap,id=net0,fd=3",
		"-device", "virtio-net-pci,netdev=net0,mac=" + o.NetMAC + ",romfile=",
		"-device", "virtio-balloon-pci",
		"-display", "none", "-nodefaults", "-no-reboot",
		"-qmp", "unix:" + o.QMPSocket + ",server=on,wait=off",
	}
	if !o.Incoming {
		args = append(args, "-kernel", o.Kernel, "-append", o.Cmdline)
	} else {
		args = append(args, "-S", "-incoming", "defer")
	}
	argv, err := loaderPrefix(o.Binary)
	if err != nil {
		return nil, err
	}
	// Deliberately NOT exec.CommandContext: the VMM must outlive the RPC
	// whose ctx launched it. The caller owns the process.
	cmd := exec.Command(argv[0], append(argv[1:], args...)...)
	cmd.Stdout = o.Stdout
	cmd.Stderr = o.Stderr
	cmd.SysProcAttr = o.SysProcAttr
	cmd.ExtraFiles = []*os.File{o.NetFile}
	proc, err := child.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("while starting QEMU: %w", err)
	}
	if err := waitForFile(o.QMPSocket, 15*time.Second); err != nil {
		proc.Stop()
		return nil, fmt.Errorf("QMP socket never appeared (QEMU exited: %s): %w", proc.Exit(), err)
	}
	q, err := qmp.Dial(o.QMPSocket)
	if err != nil {
		proc.Stop()
		return nil, fmt.Errorf("while connecting to QMP: %w", err)
	}
	return &VM{proc: proc, qmp: q}, nil
}

// Snapshot captures the stopped VM: the device-state migration stream into
// dir, plus the RAM file fsynced so its populated extents are on disk. The
// caller separately sparse-copies the RAM file into dir (SparseCopy).
func Snapshot(ctx context.Context, q *qmp.Conn, ramFile, devstatePath string) error {
	if err := q.SetIgnoreShared(); err != nil {
		return fmt.Errorf("while setting x-ignore-shared: %w", err)
	}
	if err := q.Migrate("file:" + devstatePath); err != nil {
		return fmt.Errorf("while migrating device state: %w", err)
	}
	if _, err := q.WaitMigrateCompleted(); err != nil {
		return fmt.Errorf("while waiting for the migration: %w", err)
	}
	return fsyncFile(ramFile)
}

// RestoreIncoming runs the incoming migration from the snapshot's
// device-state stream and leaves the VM paused; Cont resumes it.
func RestoreIncoming(q *qmp.Conn, devstatePath string) error {
	if err := q.SetIgnoreShared(); err != nil {
		return fmt.Errorf("while setting x-ignore-shared: %w", err)
	}
	if err := q.MigrateIncoming("file:" + devstatePath); err != nil {
		return fmt.Errorf("while starting the incoming migration: %w", err)
	}
	if _, err := q.WaitMigrateCompleted(); err != nil {
		return fmt.Errorf("while waiting for the incoming migration: %w", err)
	}
	return nil
}

// CIDFor derives a stable vhost-vsock guest CID for a sandbox id. QEMU's
// vhost-vsock shares one host-wide CID space (Cloud Hypervisor's
// hybrid-vsock instead used a unix socket per VM), so each running VM needs
// a CID unique on the node. The hash spreads them; a collision between two
// live actors fails the second QEMU launch loudly rather than corrupting
// the first. Reserved CIDs: 0 hypervisor, 1 local, 2 host.
func CIDFor(id string) uint32 {
	const minCID, maxCID = 0x10000, 0xffff0000
	h := fnv.New32a()
	h.Write([]byte("substrate:" + id))
	return minCID + h.Sum32()%(maxCID-minCID)
}

// CreateSparseRAM makes a hole-punched RAM file of the given size for a
// cold boot's memory-backend to map.
func CreateSparseRAM(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

// SparseCopy copies src to dst, copying only the populated extents, so a
// mostly-hole guest RAM image ships only its working set. The source is
// never modified, which is what lets a staged snapshot be restored again.
func SparseCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	var off int64
	buf := make([]byte, 1<<20)
	for off < fi.Size() {
		data, err := syscall.Seek(int(in.Fd()), off, unix.SEEK_DATA)
		if err != nil {
			if errors.Is(err, syscall.ENXIO) {
				break // nothing but holes to the end
			}
			return err
		}
		hole, err := syscall.Seek(int(in.Fd()), data, unix.SEEK_HOLE)
		if err != nil {
			return err
		}
		if hole > fi.Size() {
			hole = fi.Size()
		}
		for p := data; p < hole; {
			n, err := in.ReadAt(buf[:min(len(buf), int(hole-p))], p)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if n == 0 {
				break
			}
			if _, err := out.WriteAt(buf[:n], p); err != nil {
				return err
			}
			p += int64(n)
		}
		off = hole
	}
	return out.Truncate(fi.Size())
}

func fsyncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func waitForFile(path string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s never appeared", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// IsQEMUAsset reports whether a runtime asset set selects the QEMU backend:
// a "qemu" asset present where the CLH backend names "cloud-hypervisor".
func IsQEMUAsset(paths map[string]string) bool {
	_, ok := paths["qemu"]
	return ok
}
