# Kata sandbox class: Phase 0 spike

This is the decision record for adding a `kata` sandbox class that runs the
QEMU-based Kata Containers stack OpenShift Sandboxed Containers (OSC)
installs on the node, instead of the self-launched Cloud Hypervisor the
`microvm` class uses today. It records what the spike built, what was
measured, and the design decisions the measurements fix. The implementation
plan lives outside the repo; this document is what a reviewer needs to
evaluate the class itself.

## What the spike built

`tools/qemu-spike` drives a QEMU guest through the suspend and restore cycle
the class would use:

- guest RAM is a `memory-backend-file` with `share=on`, so guest writes land
  in a host file and never enter the migration stream,
- a snapshot is that file plus a device-state migration stream taken with
  the `x-ignore-shared` migration capability,
- a restore boots a fresh QEMU with `-incoming defer`, re-attaches the tap
  netdev by fd through `getfd` and `netdev_add` before `migrate-incoming`,
  and resumes,
- the guest (`tools/qemu-spike/guest-init`) heartbeats its monotonic clock
  to the serial console and serves connection counters over vsock on port
  1024, so a restore that brings RAM back is distinguishable from a reboot
  by both the clock and the counters,
- vsock can travel in the migration stream (`-vsock boot`) or be unplugged
  for the snapshot and hot-added after the restore (`-vsock post`).

`hack/spike/selinux-qemu-check.sh` catalogs how enforcing SELinux treats a
QEMU run from a staged asset directory, and `hack/spike/osc-payload-inspect.sh`
catalogs what an OSC install puts on a node.

## Measurements

Fedora 44 host, QEMU 10.2.2, KVM, guest kernel 7.3, socket netdev, three
runs per size, two cycles per run. Every cycle restored with the clock and
counters continuing and no reboot.

| RAM | snapshot | stream | RAM allocated | stage (sparse copy) | incoming |
| --- | --- | --- | --- | --- | --- |
| 256M | ~14ms | ~354KB | 51% | ~48ms | ~17ms |
| 512M | ~13ms | ~354KB | 27% | ~49ms | ~15ms |
| 1G | ~15ms | ~354KB | 14% | ~52ms | ~15ms |
| 2G | ~14ms | ~354KB | 7.9% | ~60ms | ~14ms |

The stream is device state only, so it does not grow with RAM. The
allocated portion of the RAM file is the working set the guest actually
dirtied (about 135MB here regardless of total size), so staging ships
populated regions only, and repeated cycles grow it slowly (about 135MB to
142MB over three). The restore itself is the incoming migration (~15ms)
plus `cont`; how long the harness waits to see a continuing heartbeat
(90ms to 1.1s) depends only on where in the guest's one-second heartbeat
tick the snapshot paused it. The sparse copy of 512M (~50ms) is far inside
the 500ms activation budget, before even crediting the page-cache demand
paging the real system gets from the snapshot cache.

RHCOS 9.8 node (RHEL 9 5.14 guest kernel, staged QEMU 10.2.2), three
snapshot and restore cycles per run, with the tap netdev and vsock attached:

- vsock in the migration stream: snapshot 28ms, stream 401KB, incoming
  20ms, vsock round trip after restore 11ms, guest clock continuing across
  all three restores (heartbeats 1238, 2237, 3238ms), tap reachable through
  the restored device every cycle.
- vsock unplugged for the snapshot and hot-added after the restore: same
  cycle results, with the first vsock round trip after restore at 404ms
  including the attach.

## Findings

1. **The snapshot mechanism works, repeatedly, on both kernels.**
   `memory-backend-file share=on` plus `x-ignore-shared` plus
   `migrate`/`migrate-incoming` to a file round-trips guest RAM and device
   state across consecutive cycles. The strong check passes: the vsock
   connection counters, which live only in guest RAM, keep counting up
   through every restore, and the monotonic clock continues exactly. No
   userfaultfd machinery is needed for a local restore: the RAM file maps
   as the backend and pages fault in from the page cache, which is what
   `internal/snapshotcache` already manages.

2. **vhost-vsock and virtio-net travel in the migration stream.** Three
   consecutive restores with the vsock device and a tap netdev in the
   stream work on the RHEL 9 5.14 guest kernel, with the host reaching the
   guest over vsock (11ms round trip) and over the tap after each restore.
   The unplugged/hot-add mode also works across cycles and stays available
   as a fallback, at the cost of a device attach on each resume.

3. **The guest clock resumes continuously.** The heartbeats step 1238,
   2237, 3238ms across three restores: no jump by the suspended wall time.
   The kernel marks TSC unstable after a restore and runs on kvm-clock,
   the same class of behavior that made the microvm worker keep systemd
   and chronyd on Cloud Hypervisor older than 53. No chronyd workaround
   appears necessary with this QEMU, though real workloads should confirm.

4. **A diagnostic signature to remember.** An early harness bug staged the
   original RAM file instead of the current VM's, restoring stale RAM under
   a fresh device-state stream. That mismatch alone produced
   `VQ ... Guest index inconsistent with Host index`, missed vhost
   transport resets, and guest lockups in `virtnet_send_command` —
   symptoms that look exactly like QEMU migration bugs. Seeing them in the
   real system means investigating restore staging first.

5. **A staged QEMU needs its firmware.** The binary alone cannot boot q35:
   `bios-256k.bin` comes from `seabios-bin`, the rest of the roms from
   `/usr/share/qemu`. A kata class that fetches QEMU as a SandboxConfig
   asset must ship the pc-bios tree; one that consumes the OSC payload gets
   it there. The virtio-net option ROM is avoidable with `romfile=""`,
   since no substrate guest ever PXE boots.

6. **SELinux denies a staged QEMU in a container.** Under enforcing SELinux
   a container cannot execute a QEMU staged with host labels, the
   hostPath-like case; the same files relabeled `container_file_t` run.
   A rootless `spc_t` rerun is still pending. On OpenShift the staging
   directory's labels, or the worker SCC's `seLinuxOptions`, must make the
   staged tree executable.

7. **The RHCOS node has no QEMU or Kata packages.** The class cannot use
   distro QEMU; it consumes the OSC payload or ships its own. `/dev/vhost-vsock`
   exists on the node but the `vhost_vsock` module is not loaded until
   something loads it, which the OSC payload does.

8. **vsock needs per-node CID allocation.** QEMU's vhost-vsock shares one
   host-wide CID space, where Cloud Hypervisor's hybrid-vsock used a unix
   socket per VM. A stable hash of the sandbox name with collision probing
   works, and a restore must reuse the CID the snapshot was taken with.

## Design decisions

- **D1: snapshot format.** A `MEMORY` snapshot of the kata class is the
  sparse `memory-backend-file` image plus a `file:` migration stream taken
  with `x-ignore-shared`, plus the tar layers the microvm class already
  ships. Compatibility attributes must include the QEMU and guest kernel
  identity, the analog of the microvm class's `cpu_vendor`/`cpu_model`.
- **D2: devices travel in the migration stream.** vsock and the tap
  netdev are part of the VM from creation and migrate with it, which the
  three-cycle runs validate on the RHEL 9 kernel the OSC payload uses.
  The unplugged/hot-add path is the fallback if a payload kernel or QEMU
  combination regresses.
- **D3: QMP is the control surface.** Launch with `-qmp unix:` and
  `-incoming defer`, pass tap fds with `getfd` and attach with
  `netdev_add`/`device_add` on `pcie-root-port` devices (q35's root bus
  does not hotplug), then `migrate-incoming` and `cont`.
- **D4: the asset set includes firmware**, or the class consumes the OSC
  payload's QEMU and firmware through node-path staging.
- **D5: node requirements.** `/dev/kvm`, `/dev/vhost-vsock` with the module
  loaded (OSC's install provides it), `CAP_NET_ADMIN` in the worker for the
  tap, and SELinux labels that let the worker execute the staged tree.

## Open questions

- virtiofsd `find-paths` behavior across `migrate-incoming`, the mechanism
  the whole rootfs restore path depends on. Needs a virtiofsd install; not
  covered by this spike.
- The kata-agent protocol version the OSC payload ships versus the
  `agentpb` the worker would drive, and the OSC payload's exact paths and
  kernel version on a cluster with a `KataConfig` (the inspection script
  is ready; the lab node has no OSC install).
- A rootful `spc_t` SELinux rerun.
- Delta snapshots: the RAM file grows by dirty pages only, but identifying
  them needs KVM dirty-ring tracking; the baseline ships the full sparse
  image, which the object store path already tolerates.
- These results are for the node's distro kernel as guest. The OSC
  payload's kernel is a separate build and should be re-validated with the
  same harness in Phase 3.
