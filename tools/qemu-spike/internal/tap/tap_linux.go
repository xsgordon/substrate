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

// Package tap creates the host side of the actor network: a TAP device
// carrying the gateway end of the /30. It mirrors what
// cmd/ateworker-microvm/net.go does with netlink.Tuntap, in the spike's
// default network namespace.
package tap

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// gatewayIP is the host end of the substrate actor /30.
	gatewayIP = "169.254.17.1/30"
	ifreqSize = 32
)

// Create brings up a TAP device named name and returns its queue fd. The fd
// is passed to QEMU with getfd and attached as a virtio-net netdev. Creating
// a TAP and assigning the address needs CAP_NET_ADMIN, so the driver must
// run as root to use it.
func Create(name string) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	type ifreq struct {
		Name  [16]byte
		Flags int16
		_     [ifreqSize - 18]byte
	}
	req := ifreq{Flags: unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR}
	copy(req.Name[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF %s: %w", name, errno)
	}
	if err := configureHost(name); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// configureHost assigns the gateway address and brings the link up so the
// host can reach the guest at 169.254.17.2.
func configureHost(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	addr, err := netlink.ParseAddr(gatewayIP)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("addr %s: %w", gatewayIP, err)
	}
	return netlink.LinkSetUp(link)
}
