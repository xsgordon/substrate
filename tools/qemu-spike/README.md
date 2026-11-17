# qemu-spike

Phase 0 spike for the `kata` sandbox class (see
`docs/dev/kata-sandbox-spike.md`). It answers whether QEMU can replace
Cloud Hypervisor as the microVM VMM under the constraints Agent Substrate
places on it:

- guest RAM is a shared `memory-backend-file`, so a snapshot is the file
  plus a small device-state migration stream taken with the `ignore-shared`
  migration parameter,
- restore boots a fresh QEMU, re-attaches the tap netdev by fd before the
  incoming migration, and resumes,
- the guest exposes its liveness over vhost-vsock on port 1024, the port
  the kata-agent uses.

`guest-init` is the guest's PID 1: it loads the virtio modules, brings up
the actor /30 on eth0, prints a heartbeat carrying the monotonic clock, and
serves PING and STATE over vsock. A correct restore shows the clock and
counters continuing from the snapshot; a failed one shows a fresh boot.

Run `go run ./tools/qemu-spike` for the full cycle and a latency report.
Useful invocations:

	# full matrix, unprivileged (socket netdev stands in for the tap)
	go run ./tools/qemu-spike -mem 256M,512M,1G,2G -runs 3 -cycles 2 -netdev socket

	# with vhost-vsock (needs the module loaded on the host)
	sudo modprobe vhost_vsock
	go run ./tools/qemu-spike -mem 512M -runs 1 -vsock boot

	# tap netdev, the real device path (needs root and CAP_NET_ADMIN)
	go run ./tools/qemu-spike -mem 512M -runs 1 -netdev tap

Requirements: QEMU with KVM, a kernel whose virtio drivers can be loaded
from `/lib/modules`, `xz`, and `cp` with sparse support. `vsock boot`
migrates the vhost-vsock device in the stream; `vsock post` hot-adds it
after the restore, for the case where its state does not migrate.
