#!/usr/bin/env bash
# Copyright 2026 The Agent Substrate Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Catalogs the Kata payload an OpenShift Sandboxed Containers install puts
# on a node, read-only. The kata sandbox class would run the payload's QEMU
# and kata-agent directly, the way ateworker-microvm runs Cloud Hypervisor
# and the stock kata-agent today, so the class needs the exact paths,
# versions, and SELinux state this prints.
#
# Run on a worker node with the payload installed:
#   ssh core@<node> hack/spike/osc-payload-inspect.sh
# or through a debug pod:
#   oc debug node/<node> -- chroot /host hack/spike/osc-payload-inspect.sh
#
# Without a KataConfig the script still reports the RHCOS baseline, which
# is what a node needs before the operator installs on it.

set -euo pipefail

say() { printf '\n== %s ==\n' "$1"; }

say "OS and kernel"
uname -r
grep PRETTY /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || true

say "SELinux"
getenforce 2>/dev/null || echo "not available"
sestatus 2>/dev/null | head -4 || true

say "virtualization devices"
ls -l /dev/kvm /dev/vhost-vsock /dev/net/tun 2>&1 || true

say "loaded modules"
lsmod | grep -E '^(kvm|vhost_vsock|vhost|tun|vmw_vsock)' || echo "none of kvm/vhost_vsock/tun loaded"

say "kata and qemu packages"
rpm -qa 2>/dev/null | grep -Ei 'kata|qemu' | sort || echo "no kata or qemu packages"

say "kata payload locations"
for d in /usr/libexec/kata-containers /opt/kata /usr/lib/kata-containers \
  /usr/share/kata-containers /etc/kata-containers; do
  if [[ -e "$d" ]]; then
    echo "$d:"
    ls "$d" 2>/dev/null | sed 's/^/  /'
  fi
done

say "kata runtime versions"
for b in kata-runtime containerd-shim-kata-v2 qemu-system-x86_64; do
  p=$(command -v "$b" 2>/dev/null || true)
  [[ -z "$p" ]] && p=$(ls /usr/libexec/kata-containers/"$b" 2>/dev/null || true)
  if [[ -n "$p" ]]; then
    echo "$p: $("$p" --version 2>&1 | head -1)"
  else
    echo "$b: not found"
  fi
done

say "kata configuration"
for f in /etc/kata-containers/configuration.toml \
  /usr/share/kata-containers/defaults/configuration.toml; do
  if [[ -f "$f" ]]; then
    echo "$f:"
    grep -Ev '^\s*(#|$)' "$f" | head -40 | sed 's/^/  /'
  fi
done

say "SELinux labels of payload binaries"
find /usr/libexec/kata-containers /opt/kata -maxdepth 3 -type f \
  \( -name 'qemu*' -o -name 'kata-*' -o -name 'virtiofsd' \) \
  -exec stat -c '%C %n' {} \; 2>/dev/null | head -20 || true

say "runtime classes (from a node with oc, else skip)"
command -v oc >/dev/null 2>&1 && oc get runtimeclass 2>/dev/null || \
  echo "oc not available on this node"
