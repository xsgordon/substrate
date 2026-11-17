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
