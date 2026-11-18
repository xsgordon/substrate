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

// qemu-spike drives a QEMU guest through the snapshot and restore cycle
// proposed for the kata sandbox class: guest RAM is a shared
// memory-backend-file, a snapshot is that file plus a device-state
// migration stream taken with the ignore-shared parameter, and a restore
// boots a fresh QEMU, re-attaches the tap netdev by fd before the incoming
// migration, and resumes. It reports whether guest state survives (the
// monotonic heartbeat and the vsock counters continue instead of rebooting)
// and what each phase costs.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.ate.dev/substrate/tools/qemu-spike/internal/cpio"
	"go.ate.dev/substrate/tools/qemu-spike/internal/qmp"
	"go.ate.dev/substrate/tools/qemu-spike/internal/tap"
	"go.ate.dev/substrate/tools/qemu-spike/internal/vsockcid"
	"golang.org/x/sys/unix"
)

var (
	flagWorkdir   = flag.String("workdir", "/tmp/qemu-spike", "scratch directory")
	flagMem       = flag.String("mem", "512M,1G", "comma-separated guest RAM sizes to test")
	flagRuns      = flag.Int("runs", 3, "runs per RAM size")
	flagCycles    = flag.Int("cycles", 2, "snapshot and restore cycles per run")
	flagVsock     = flag.String("vsock", "boot", "vsock device: boot (in the migration stream), post (hot-added after restore), off")
	flagNetdev    = flag.String("netdev", "tap", "netdev: tap (needs root), socket (unprivileged fallback), off")
	flagQEMU      = flag.String("qemu", "qemu-system-x86_64", "QEMU binary")
	flagKernel    = flag.String("kernel", "", "guest kernel (default /boot/vmlinuz-$(uname -r))")
	flagGuestInit = flag.String("guest-init", "", "prebuilt guest init binary (default: built from source)")
	flagKeep      = flag.Bool("keep", false, "keep per-run directories")
	flagTimeout   = flag.Duration("timeout", 90*time.Second, "guest readiness timeout")
)

// guestMAC mirrors the substrate actor guest MAC, which is fixed because a
// restored VM's ARP cache still holds it.
const guestMAC = "02:a8:1e:00:00:02"

// guestModules lists the kernel modules the initramfs carries, in the
// dependency order guest-init loads them.
var guestModules = []string{"failover", "net_failover", "virtio_net", "vsock", "vmw_vsock_virtio_transport_common", "vmw_vsock_virtio_transport"}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qemu-spike:", err)
		os.Exit(1)
	}
}

func run() error {
	abs, err := filepath.Abs(*flagWorkdir)
	if err != nil {
		return err
	}
	*flagWorkdir = abs
	if err := os.RemoveAll(*flagWorkdir); err != nil {
		return err
	}
	if err := os.MkdirAll(*flagWorkdir, 0o755); err != nil {
		return err
	}
	guestBin, err := buildGuestInit()
	if err != nil {
		return err
	}
	initramfs, err := buildInitramfs(guestBin)
	if err != nil {
		return err
	}
	vsockMode := *flagVsock
	if vsockMode != "off" && !vhostVsockAvailable() {
		fmt.Println("vhost-vsock unavailable (module not loaded?); running with vsock off")
		vsockMode = "off"
	}
	netdevMode := *flagNetdev
	kernel := *flagKernel
	if kernel == "" {
		kernel = "/boot/vmlinuz-" + kernelRelease()
	}

	mems := strings.Split(*flagMem, ",")
	var rows []report
	for _, mem := range mems {
		for i := 1; i <= *flagRuns; i++ {
			row, err := runCycle(fmt.Sprintf("%s-%d", mem, i), mem, kernel, initramfs, vsockMode, netdevMode)
			if err != nil {
				row.Error = err.Error()
			}
			rows = append(rows, row)
			printRow(row)
		}
	}
	writeReport(rows)
	return nil
}

// report is one run's measurements.
type report struct {
	Mem        string `json:"mem"`
	Run        string `json:"run"`
	Cycles     int    `json:"cycles"`
	SnapshotMS int64  `json:"snapshot_ms"`
	StreamByte int64  `json:"migration_stream_bytes"`
	RamTotal   int64  `json:"ram_total_bytes"`
	RamAlloc   int64  `json:"ram_allocated_bytes"`
	StageMS    int64  `json:"stage_ms"`
	IncomingMS int64  `json:"incoming_ms"`
	BootToHBMS int64  `json:"boot_to_heartbeat_ms"`
	PongMS     int64  `json:"cont_to_pong_ms"`
	StateKept  bool   `json:"state_continuous"`
	NoReboot   bool   `json:"no_reboot"`
	VsockOK    bool   `json:"vsock_ok"`
	NetOK      bool   `json:"net_ok"`
	NetdevMode string `json:"netdev_mode"`
	Error      string `json:"error,omitempty"`
}

// runCycle boots a guest, snapshots and restores it flagCycles times, and
// returns the measurements.
func runCycle(name, mem, kernel, initramfs, vsockMode, netdevMode string) (report, error) {
	row := report{Mem: mem, Run: name, Cycles: *flagCycles, NetdevMode: netdevMode}
	dir := filepath.Join(*flagWorkdir, "run-"+name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return row, err
	}
	alloc := vsockcid.New()
	cid := alloc.Allocate(name)
	defer alloc.Release(name)

	ram := filepath.Join(dir, "ram.bin")
	if err := createSparse(ram, memBytes(mem)); err != nil {
		return row, err
	}
	src, err := bootVM(vmCfg{
		mem: mem, ramPath: ram, dir: dir, tag: "c0",
		kernel: kernel, initrd: initramfs,
		vsockCID: cidFor(vsockMode, cid),
	})
	if err != nil {
		return row, err
	}
	// Attach the netdev while the kernel is still booting, so eth0 usually
	// exists before guest-init configures it.
	row.NetOK, netdevMode = attachNetdev(src, netdevMode)
	row.NetdevMode = netdevMode
	if err := waitMarker(src.consolePath, "GUEST-READY", *flagTimeout); err != nil {
		src.kill()
		return row, fmt.Errorf("guest never became ready: %w", err)
	}
	if netdevMode == "tap" {
		if err := pingGuest(); err != nil {
			row.NetOK = false
			row.addError("ping before snapshot: %v", err)
		}
	}

	// lastState carries the guest's vsock counters from one observation to
	// the next; a restore that continues RAM produces strictly larger ones.
	var lastState guestState
	if vsockMode == "boot" {
		sv, err := vsockState(cid)
		if err != nil {
			row.addError("vsock before snapshot: %v", err)
		} else {
			lastState, row.VsockOK = sv, true
		}
	}
	// vsockAttached tracks the post-mode hot-added device, which is
	// unplugged again before each snapshot.
	vsockAttached := false

	for cycle := 1; cycle <= *flagCycles; cycle++ {
		// The cycle's source is the previous cycle's restored VM.
		devstate := filepath.Join(dir, fmt.Sprintf("devstate-c%d.bin", cycle))
		lastHB := lastHeartbeat(src.consolePath)

		// vhost-vsock state does not survive being migrated twice: the
		// second restore trips a vhost virtqueue index inconsistency and
		// the guest misses the transport reset. In post mode the device
		// therefore travels outside the stream, unplugged for the
		// snapshot and re-attached after the restore.
		if vsockAttached {
			if err := detachVsock(src); err != nil {
				src.kill()
				return row, fmt.Errorf("vsock detach cycle %d: %w", cycle, err)
			}
			vsockAttached = false
		}

		start := time.Now()
		stats, err := snapshotVM(src, devstate)
		row.SnapshotMS = time.Since(start).Milliseconds()
		if err != nil {
			src.kill()
			return row, fmt.Errorf("snapshot cycle %d: %w", cycle, err)
		}
		row.StreamByte = stats.StreamByte
		row.RamTotal, row.RamAlloc = stats.RamTotal, stats.RamAlloc

		start = time.Now()
		restoreRam := filepath.Join(dir, fmt.Sprintf("ram-restore-c%d.bin", cycle))
		restoreState := filepath.Join(dir, fmt.Sprintf("devstate-restore-c%d.bin", cycle))
		// Stage the CURRENT VM's RAM file: after the first cycle the
		// running VM's backend is the previous restore's staged copy, not
		// the original ram.bin. Stale RAM under a fresh device-state
		// stream produces exactly the virtqueue chaos a broken restore
		// would.
		for _, cp := range [][2]string{{src.cfg.ramPath, restoreRam}, {devstate, restoreState}} {
			// Sparse copy keeps holes in the RAM image, the way the
			// object store would ship only populated regions.
			if out, err := exec.Command("cp", "--sparse=always", cp[0], cp[1]).CombinedOutput(); err != nil {
				src.kill()
				return row, fmt.Errorf("stage cycle %d: %v: %s", cycle, err, out)
			}
		}
		row.StageMS = time.Since(start).Milliseconds()

		src.kill()

		bootStart := time.Now()
		dst, err := bootVM(vmCfg{
			mem: mem, ramPath: restoreRam, dir: dir, tag: fmt.Sprintf("c%d", cycle),
			incoming: true,
			vsockCID: cidFor(vsockMode, cid),
		})
		if err != nil {
			return row, fmt.Errorf("restore boot cycle %d: %w", cycle, err)
		}
		src = dst

		// The netdev and its fd must exist before the incoming migration
		// starts, because the migration stream carries the device.
		if netdevMode != "off" {
			if err := attachNetdevOne(dst, netdevMode); err != nil {
				dst.kill()
				return row, fmt.Errorf("netdev on restore cycle %d: %w", cycle, err)
			}
		}

		incomingStart := time.Now()
		if err := restoreVM(dst, restoreState); err != nil {
			dst.kill()
			return row, fmt.Errorf("incoming cycle %d: %w", cycle, err)
		}
		row.IncomingMS = time.Since(incomingStart).Milliseconds()

		if _, err := waitNewHeartbeat(dst.consolePath, lastHB, *flagTimeout); err != nil {
			dst.kill()
			return row, fmt.Errorf("no continuing heartbeat after restore cycle %d: %w", cycle, err)
		}
		row.BootToHBMS = time.Since(bootStart).Milliseconds()
		row.NoReboot = !markerPresent(dst.consolePath, "GUEST-READY")

		if vsockMode == "post" {
			if err := hotAddVsock(dst, cid); err != nil {
				dst.kill()
				return row, fmt.Errorf("hot-add vsock cycle %d: %w", cycle, err)
			}
			vsockAttached = true
		}
		if vsockMode != "off" {
			start = time.Now()
			sv, err := vsockState(cid)
			if err != nil {
				row.addError("vsock after restore cycle %d: %v", cycle, err)
				dst.kill()
				return row, fmt.Errorf("vsock after restore cycle %d: %w", cycle, err)
			}
			row.PongMS = time.Since(start).Milliseconds()
			row.VsockOK = true
			// The counters live only in guest RAM, so a restore that
			// brought RAM back produces strictly larger ones.
			if lastState.ok {
				row.StateKept = sv.served > lastState.served && sv.ms > lastState.ms
				if !row.StateKept {
					row.addError("guest state reset after restore cycle %d: %s", cycle, sv.raw)
				}
			} else {
				// No earlier observation to compare against.
				row.StateKept = row.BootToHBMS > 0
			}
			lastState = sv
		} else {
			// Without vsock, continuity rides on the heartbeat alone.
			row.StateKept = row.BootToHBMS > 0
		}
		if netdevMode == "tap" {
			if err := pingGuest(); err != nil {
				row.NetOK = false
				row.addError("ping after restore cycle %d: %v", cycle, err)
			}
		}
	}
	src.kill()
	if !*flagKeep {
		os.RemoveAll(dir)
	}
	return row, nil
}

func (r *report) addError(format string, args ...any) {
	r.Error = strings.TrimSpace(r.Error + "; " + fmt.Sprintf(format, args...))
}

// cidFor returns the vsock CID to bake into the VM config, or 0 for none.
func cidFor(mode string, cid uint32) uint32 {
	if mode == "boot" {
		return cid
	}
	return 0
}

// vm is one running QEMU process.
type vm struct {
	cmd         *exec.Cmd
	qmp         *qmp.Conn
	cfg         vmCfg
	consolePath string
}

type vmCfg struct {
	mem      string
	ramPath  string
	dir      string
	tag      string
	incoming bool
	kernel   string
	initrd   string
	vsockCID uint32
}

// bootVM launches QEMU and connects to its QMP socket. The guest RAM is the
// shared memory-backend-file: whatever the guest writes lands in the file,
// and the migration stream never carries it.
func bootVM(cfg vmCfg) (*vm, error) {
	console := filepath.Join(cfg.dir, "console-"+cfg.tag+".log")
	qmpPath := filepath.Join(cfg.dir, "qmp-"+cfg.tag+".sock")
	qemuLog, err := os.Create(filepath.Join(cfg.dir, "qemu-"+cfg.tag+".log"))
	if err != nil {
		return nil, err
	}
	args := []string{
		*flagQEMU,
		"-enable-kvm", "-cpu", "host",
		"-machine", "q35,memory-backend=mem",
		"-smp", "2",
		"-m", cfg.mem,
		"-object", fmt.Sprintf("memory-backend-file,id=mem,size=%s,mem-path=%s,share=on", cfg.mem, cfg.ramPath),
		"-display", "none",
		"-serial", "file:" + console,
		"-monitor", "none",
		"-nodefaults", "-no-reboot",
		"-qmp", "unix:" + qmpPath + ",server=on,wait=off",
	}
	if cfg.kernel != "" {
		args = append(args, "-kernel", cfg.kernel, "-initrd", cfg.initrd, "-append", "console=ttyS0 panic=-1")
	}
	if cfg.incoming {
		args = append(args, "-incoming", "defer")
	}
	if cfg.vsockCID != 0 {
		args = append(args, "-device", fmt.Sprintf("vhost-vsock-pci,guest-cid=%d", cfg.vsockCID))
	}
	// q35's root bus does not hotplug; devices added over QMP sit on root
	// ports. The ports exist on both ends of a migration, so device_add
	// before migrate-incoming lands on the same slots.
	args = append(args,
		"-device", "pcie-root-port,id=rp-net,chassis=0,slot=0",
		"-device", "pcie-root-port,id=rp-vsock,chassis=1,slot=0",
	)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = qemuLog
	cmd.Stderr = qemuLog
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	v := &vm{cmd: cmd, cfg: cfg, consolePath: console}
	if err := waitFile(qmpPath, 10*time.Second); err != nil {
		v.kill()
		return nil, fmt.Errorf("qmp socket: %w (see %s)", err, qemuLog.Name())
	}
	v.qmp, err = qmp.Dial(qmpPath)
	if err != nil {
		v.kill()
		return nil, err
	}
	return v, nil
}

func (v *vm) kill() {
	if v.qmp != nil {
		v.qmp.Close()
	}
	v.cmd.Process.Signal(unix.SIGTERM)
	done := make(chan struct{})
	go func() { v.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		v.cmd.Process.Kill()
		<-done
	}
}

type snapStats struct {
	StreamByte int64
	RamTotal   int64
	RamAlloc   int64
}

// snapshotVM pauses the VM and takes the device-state migration stream with
// ignore-shared, then flushes the RAM file to disk.
func snapshotVM(v *vm, devstate string) (snapStats, error) {
	var s snapStats
	if err := v.qmp.Stop(); err != nil {
		return s, err
	}
	if err := v.qmp.SetIgnoreShared(); err != nil {
		return s, err
	}
	if err := migrate(v.qmp, devstate); err != nil {
		return s, err
	}
	stats, err := v.qmp.WaitMigrateCompleted()
	if err != nil {
		return s, err
	}
	if stats.Ram != nil {
		s.StreamByte = stats.Ram.TransferredByte
	}
	if err := syncFile(v.cfg.ramPath); err != nil {
		return s, err
	}
	if st, err := os.Stat(v.cfg.ramPath); err == nil {
		s.RamTotal = st.Size()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			s.RamAlloc = sys.Blocks * 512
		}
	}
	return s, nil
}

// migrate starts the outgoing migration, preferring the file: URI and
// falling back to exec:cat on QEMUs without it.
func migrate(c *qmp.Conn, path string) error {
	if err := c.Migrate("file:" + path); err == nil {
		return nil
	}
	return c.Migrate("exec:cat > " + path)
}

// restoreVM runs the incoming migration and resumes the VM.
func restoreVM(v *vm, devstate string) error {
	if err := v.qmp.SetIgnoreShared(); err != nil {
		return err
	}
	err := v.qmp.MigrateIncoming("file:" + devstate)
	if err != nil {
		if err2 := v.qmp.MigrateIncoming("exec:cat " + devstate); err2 != nil {
			return fmt.Errorf("%v (file fallback also failed: %v)", err, err2)
		}
	}
	if _, err := v.qmp.WaitMigrateCompleted(); err != nil {
		return err
	}
	return v.qmp.Cont()
}

// attachNetdev adds the virtio-net backend by fd, falling back from tap to
// socket when the process lacks CAP_NET_ADMIN. It reports whether the guest
// network came up.
func attachNetdev(v *vm, mode string) (bool, string) {
	err := attachNetdevOne(v, mode)
	if err == nil {
		return true, mode
	}
	if mode == "tap" {
		fmt.Printf("tap unavailable (%v); falling back to socket netdev\n", err)
		if err := attachNetdevOne(v, "socket"); err == nil {
			return true, "socket"
		}
	}
	fmt.Printf("netdev attach failed: %v\n", err)
	return false, "off"
}

// attachNetdevOne passes the backend fd with getfd and attaches the
// virtio-net device. On the restore side this must happen before the
// incoming migration starts.
func attachNetdevOne(v *vm, mode string) error {
	var f *os.File
	var netdevType string
	switch mode {
	case "tap":
		tapF, err := tap.Create("tap_spike")
		if err != nil {
			return err
		}
		f, netdevType = tapF, "tap"
	case "socket":
		// A connected TCP socket stands in for the tap when the driver
		// runs unprivileged. The topology is what matters for migration.
		conn, err := localConnPair()
		if err != nil {
			return err
		}
		f, netdevType = conn, "socket"
	default:
		return nil
	}
	defer f.Close()
	if err := v.qmp.GetFD("netfd", int(f.Fd())); err != nil {
		return err
	}
	if _, err := v.qmp.Command("netdev_add", map[string]any{
		"type": netdevType, "id": "net0", "fd": "netfd",
	}); err != nil {
		return err
	}
	_, err := v.qmp.Command("device_add", map[string]any{
		"driver": "virtio-net-pci", "id": "nic0", "netdev": "net0",
		"mac": guestMAC, "bus": "rp-net",
		// No guest PXE or EFI boots from this NIC, so skip the option
		// ROM: it is another firmware blob the asset would have to ship.
		"romfile": "",
	})
	return err
}

// hotAddVsock attaches the vsock device after a restore, for the mode where
// the device is not part of the migration stream.
func hotAddVsock(v *vm, cid uint32) error {
	_, err := v.qmp.Command("device_add", map[string]any{
		"driver": "vhost-vsock-pci", "id": "vsock0", "guest-cid": cid, "bus": "rp-vsock",
	})
	return err
}

// localConnPair returns one end of a loopback TCP connection, for the
// socket netdev fallback.
func localConnPair() (*os.File, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn).File()
}

func pingGuest() error {
	out, err := exec.Command("ping", "-c", "1", "-W", "2", "169.254.17.2").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

// guestState is the guest's answer to STATE: the vsock connection counter
// and the monotonic clock, both of which live only in guest RAM.
type guestState struct {
	served int64
	ms     int64
	ok     bool
	raw    string
}

// vsockState dials the guest on its CID and reads its STATE reply.
func vsockState(cid uint32) (guestState, error) {
	line, err := vsockRoundtrip(cid, "STATE")
	if err != nil {
		return guestState{}, err
	}
	var sv guestState
	sv.raw = line
	fields := strings.Fields(line)
	if len(fields) == 3 && fields[0] == "STATE" {
		if s, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			if m, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
				sv.served, sv.ms, sv.ok = s, m, true
			}
		}
	}
	if !sv.ok {
		return sv, fmt.Errorf("bad STATE reply %q", line)
	}
	return sv, nil
}

// vsockRoundtrip dials the guest on its CID and returns its reply line.
func vsockRoundtrip(cid uint32, request string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 10; attempt++ {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
		if err != nil {
			return "", err
		}
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
		if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: 1024}); err != nil {
			unix.Close(fd)
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		unix.Write(fd, []byte(request+"\n"))
		f := os.NewFile(uintptr(fd), "vsock")
		line, err := bufio.NewReader(f).ReadString('\n')
		f.Close()
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		return strings.TrimSpace(line), nil
	}
	return "", lastErr
}

// detachVsock unplugs the hot-added vsock device so the snapshot's
// migration stream does not carry its state.
func detachVsock(v *vm) error {
	if _, err := v.qmp.Command("device_del", map[string]any{"id": "vsock0"}); err != nil {
		return err
	}
	return v.qmp.WaitDeviceDeleted(10 * time.Second)
}

func vhostVsockAvailable() bool {
	f, err := os.OpenFile("/dev/vhost-vsock", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// buildGuestInit compiles guest-init as a static binary for the host
// platform.
func buildGuestInit() (string, error) {
	if *flagGuestInit != "" {
		return *flagGuestInit, nil
	}
	src, err := moduleDir()
	if err != nil {
		return "", err
	}
	out := filepath.Join(*flagWorkdir, "guest-init")
	cmd := exec.Command("go", "build", "-C", src, "-o", out, "./guest-init")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if outb, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build guest-init: %v: %s", err, outb)
	}
	return out, nil
}

// buildInitramfs packs guest-init and the virtio modules into a gzipped
// newc archive.
func buildInitramfs(guestBin string) (string, error) {
	modRoot := "/lib/modules/" + kernelRelease() + "/kernel"
	modPaths := map[string]string{
		"failover":                          "net/core/failover.ko.xz",
		"net_failover":                      "drivers/net/net_failover.ko.xz",
		"virtio_net":                        "drivers/net/virtio_net.ko.xz",
		"vsock":                             "net/vmw_vsock/vsock.ko.xz",
		"vmw_vsock_virtio_transport_common": "net/vmw_vsock/vmw_vsock_virtio_transport_common.ko.xz",
		"vmw_vsock_virtio_transport":        "net/vmw_vsock/vmw_vsock_virtio_transport.ko.xz",
	}
	guest, err := os.ReadFile(guestBin)
	if err != nil {
		return "", err
	}
	outPath := filepath.Join(*flagWorkdir, "initramfs.cpio.gz")
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	w := cpio.NewWriter(gz)
	for _, dir := range []string{"dev/", "proc/", "sys/", "modules/"} {
		if err := w.Directory(dir); err != nil {
			return "", err
		}
	}
	if err := w.File("init", 0o755, guest); err != nil {
		return "", err
	}
	for _, name := range guestModules {
		data, err := decompressXZ(filepath.Join(modRoot, modPaths[name]))
		if err != nil {
			return "", fmt.Errorf("module %s: %w", name, err)
		}
		if err := w.File("modules/"+name+".ko", 0o644, data); err != nil {
			return "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return outPath, nil
}

func kernelRelease() string {
	var uts unix.Utsname
	unix.Uname(&uts)
	return charsToString(uts.Release[:])
}

func charsToString(b []byte) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

func moduleDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate module directory")
	}
	return filepath.Dir(file), nil
}

// decompressXZ unpacks a kernel module, which Fedora stores compressed.
func decompressXZ(path string) ([]byte, error) {
	out, err := exec.Command("xz", "-dc", path).Output()
	if err != nil {
		return nil, fmt.Errorf("xz %s: %w", path, err)
	}
	return out, nil
}

func memBytes(mem string) int64 {
	suffix := map[byte]int64{'K': 1 << 10, 'M': 1 << 20, 'G': 1 << 30}
	n, err := strconv.ParseInt(strings.TrimRight(mem, "KMGkmg"), 10, 64)
	if err != nil {
		return 0
	}
	if s, ok := suffix[strings.ToUpper(mem[len(mem)-1:])[0]]; ok {
		return n * s
	}
	return n
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// createSparse makes a hole-punched file of the given size for the
// memory-backend to map.
func createSparse(path string, size int64) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

func waitFile(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
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

func waitMarker(path, marker string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if markerPresent(path, marker) {
			return nil
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(path)
			return fmt.Errorf("%q not in %s; console so far:\n%s", marker, path, data)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func markerPresent(path, marker string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.Contains(string(data), marker)
}

// lastHeartbeat returns the millisecond value of the newest heartbeat line,
// or -1 when none was printed yet.
func lastHeartbeat(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	var last int64 = -1
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "HEARTBEAT" {
			if ms, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				last = ms
			}
		}
	}
	return last
}

// waitNewHeartbeat waits for a heartbeat carrying a later millisecond value
// than the snapshot's last one. Only a guest whose clock came back from RAM
// can produce it.
func waitNewHeartbeat(path string, above int64, timeout time.Duration) (int64, error) {
	deadline := time.Now().Add(timeout)
	for {
		if ms := lastHeartbeat(path); ms > above {
			return ms, nil
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(path)
			return 0, fmt.Errorf("no heartbeat above %d; console so far:\n%s", above, data)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func printRow(r report) {
	state := "no"
	if r.StateKept {
		state = "yes"
	}
	fmt.Printf("%-6s run=%-8s snap=%5dms stream=%7dB ram=%5.1f%% stage=%4dms incoming=%4dms boot→hb=%6dms pong=%5dms state=%s vsock=%v net=%v",
		r.Mem, r.Run, r.SnapshotMS, r.StreamByte,
		percent(r.RamAlloc, r.RamTotal), r.StageMS, r.IncomingMS, r.BootToHBMS, r.PongMS,
		state, r.VsockOK, r.NetOK)
	if r.Error != "" {
		fmt.Printf(" err=%s", r.Error)
	}
	fmt.Println()
}

func percent(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b) * 100
}

func writeReport(rows []report) {
	data, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(*flagWorkdir, "report.json"), data, 0o644); err != nil {
		fmt.Println("writing report:", err)
	}
	fmt.Printf("report written to %s\n", filepath.Join(*flagWorkdir, "report.json"))
}
