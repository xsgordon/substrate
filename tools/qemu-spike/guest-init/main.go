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

// guest-init is PID 1 of the qemu-spike guest. It mounts the pseudo
// filesystems, loads the virtio modules the Fedora kernel ships as modules,
// brings up eth0 with the actor /30 address, prints a heartbeat carrying the
// monotonic clock, and serves a tiny request protocol over vsock. The host
// driver uses the heartbeat and the vsock counters to tell a restored guest
// (clock and counters continue) from a rebooted one (everything restarts).
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// guestIP and gateway mirror the substrate actor /30 so the network
	// result transfers to the real worker.
	guestIP   = "169.254.17.2/30"
	vsockPort = 1024
)

// loadOrder lists the guest modules in dependency order. The virtio_pci
// transport is built into the Fedora kernel; the rest ship as modules.
var loadOrder = []string{
	"failover",
	"net_failover",
	"virtio_net",
	"vsock",
	"vmw_vsock_virtio_transport_common",
	"vmw_vsock_virtio_transport",
}

var (
	start   = time.Now()
	console *os.File
	// served counts vsock connections. It lives only in guest memory, so a
	// correct restore keeps counting where the snapshot left off.
	served int64
)

func main() {
	if err := mountAll(); err != nil {
		// Nothing else works without /dev, so PID 1 cannot continue.
		panic(err)
	}
	openConsole()
	logf("GUEST-INIT starting")
	loadModules()
	setupNetwork()
	go heartbeat()
	listenVsock()
}

func mountAll() error {
	for _, m := range []struct{ src, target, typ string }{
		{"devtmpfs", "/dev", "devtmpfs"},
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
	} {
		if err := unix.Mount(m.src, m.target, m.typ, 0, ""); err != nil {
			return fmt.Errorf("mount %s: %w", m.target, err)
		}
	}
	return nil
}

// openConsole makes /dev/console the standard file descriptors. The kernel
// gives PID 1 no open fds when the initramfs carries no console node.
func openConsole() {
	f, err := os.OpenFile("/dev/console", os.O_RDWR, 0)
	if err != nil {
		return
	}
	for fd := 0; fd < 3; fd++ {
		unix.Dup3(int(f.Fd()), fd, 0)
	}
	console = f
}

func logf(format string, args ...any) {
	if console == nil {
		return
	}
	fmt.Fprintf(console, format+"\n", args...)
}

// loadModules loads the staged .ko files with finit_module. A module that is
// already loaded (EEXIST) is fine; anything else is reported and skipped so
// the guest still boots far enough to test the rest.
func loadModules() {
	for _, name := range loadOrder {
		path := "/modules/" + name + ".ko"
		f, err := os.Open(path)
		if err != nil {
			logf("MODULE-MISSING %s: %v", name, err)
			continue
		}
		err = unix.FinitModule(int(f.Fd()), "", 0)
		f.Close()
		if err == nil || err == unix.EEXIST {
			logf("MODULE-LOADED %s", name)
		} else {
			logf("MODULE-ERROR %s: %v", name, err)
		}
	}
}

func setupNetwork() {
	link, err := netlink.LinkByName("eth0")
	if err != nil {
		logf("NET-ERROR no eth0: %v", err)
		return
	}
	addr, err := netlink.ParseAddr(guestIP)
	if err != nil {
		logf("NET-ERROR parse %s: %v", guestIP, err)
		return
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		logf("NET-ERROR addr: %v", err)
		return
	}
	if err := netlink.LinkSetUp(link); err != nil {
		logf("NET-ERROR up: %v", err)
		return
	}
	logf("NET-READY eth0 %s", guestIP)
}

// heartbeat prints one line a second. After a restore the millisecond value
// keeps climbing from the original boot, which is the cheapest visible proof
// that RAM came back rather than a fresh kernel.
func heartbeat() {
	for range time.Tick(time.Second) {
		logf("HEARTBEAT %d", time.Since(start).Milliseconds())
	}
}

// listenVsock serves the spike protocol on vsock port 1024, the port the
// kata-agent listens on. PING measures the round trip; STATE reports the
// connection counter and the monotonic clock.
func listenVsock() {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		logf("VSOCK-ERROR socket: %v", err)
		return
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: vsockPort}); err != nil {
		logf("VSOCK-ERROR bind: %v", err)
		return
	}
	if err := unix.Listen(fd, 8); err != nil {
		logf("VSOCK-ERROR listen: %v", err)
		return
	}
	logf("VSOCK-READY port %d", vsockPort)
	for {
		nfd, _, err := unix.Accept(fd)
		if err != nil {
			logf("VSOCK-ERROR accept: %v", err)
			return
		}
		served++
		go serve(nfd)
	}
}

func serve(fd int) {
	defer unix.Close(fd)
	r := bufio.NewReader(os.NewFile(uintptr(fd), "vsock"))
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	var reply string
	switch strings.TrimSpace(line) {
	case "PING":
		reply = fmt.Sprintf("PONG %d", time.Since(start).Milliseconds())
	case "STATE":
		reply = fmt.Sprintf("STATE %d %d", served, time.Since(start).Milliseconds())
	default:
		reply = "ECHO " + strings.TrimSpace(line)
	}
	unix.Write(fd, []byte(reply+"\n"))
}
