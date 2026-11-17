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
# Catalogs how enforcing SELinux treats a QEMU run from a runtime-staged
# asset directory, the way an ateworker kata class would run it on an
# OpenShift node. Today no sandbox binary is node-installed and nothing
# runs from a hostPath-staged path inside a container, so this is new
# territory for the substrate security model.
#
# Three scenarios, each running the staged QEMU inside a container:
#   1. hostPath-style bind mount, label untouched (what a plain hostPath
#      volume gives the worker pod today)
#   2. same mount with the container relabeled spc_t, the "super
#      privileged container" type OpenShift grants via a custom SCC
#   3. same mount relabeled container_file_t (podman :Z, or what a
#      properly labeled staging directory would give)
#
# Also runs the staged QEMU outside any container as a baseline.
#
# Usage: hack/spike/selinux-qemu-check.sh [workdir]
# Needs podman. AVC details land in the audit log; run
#   sudo ausearch -m avc -ts recent
# afterwards to see them.

set -euo pipefail

WORKDIR="${1:-/tmp/qemu-selinux-spike}"
QEMU="${QEMU:-$(command -v qemu-system-x86_64 || true)}"
IMAGE="${IMAGE:-quay.io/libpod/fedora-minimal:latest}"

if [[ -z "$QEMU" ]]; then
  echo "no qemu-system-x86_64 on PATH; set QEMU=/path/to/qemu" >&2
  exit 1
fi
command -v podman >/dev/null || { echo "podman is required" >&2; exit 1; }
command -v ldd >/dev/null || { echo "ldd is required" >&2; exit 1; }

STAGE="$WORKDIR/assets"
mkdir -p "$STAGE/lib"

# Stage the QEMU binary and its shared libraries the way atelet stages
# sandbox assets: a self-contained directory that does not depend on the
# node's package layout.
echo "staging $QEMU and its libraries into $STAGE"
cp -L "$QEMU" "$STAGE/qemu-system-x86_64"
# ldd prints dependencies as "lib => /path (addr)" and the dynamic
# interpreter as "/path (addr)" with no arrow; both are needed.
while read -r lib; do
  [[ -f "$lib" ]] && cp -L "$lib" "$STAGE/lib/"
done < <(ldd "$QEMU" | awk '$2 == "=>" { print $3 } $1 ~ /^\// { print $1 }')

label() { stat -c %C "$1" 2>/dev/null || echo unknown; }

# Run through the staged dynamic linker, so the staged tree is
# self-contained and a failure means SELinux rather than a host/container
# glibc mismatch.
LOADER="$STAGE/lib/ld-linux-x86-64.so.2"
run_staged() { "$LOADER" --library-path "$STAGE/lib" "$STAGE/qemu-system-x86_64" --version; }

echo
echo "SELinux mode: $(getenforce 2>/dev/null || echo unavailable)"
echo "staged binary label: $(label "$STAGE/qemu-system-x86_64")"
echo
echo "== baseline: staged QEMU outside any container =="
if run_staged >/dev/null 2>&1; then
  echo "RESULT: runs (unconfined host session)"
else
  echo "RESULT: DENIED"
fi

pod() {
  podman run --rm --device /dev/kvm \
    -v "$STAGE":/assets:ro \
    "$@" "$IMAGE" \
    /assets/lib/ld-linux-x86-64.so.2 --library-path /assets/lib \
    /assets/qemu-system-x86_64 --version
}

# Show the tail of a container run without podman's pull progress noise.
show_error() {
  grep -vE '^(Copying|Writing|Resolved|Trying|Storing|Getting|Fetching|Loading|Loaded|Extracting|Configuring|Applying)' <<<"$1" | tail -5 | sed 's/^/    /'
}

echo
echo "== 1. hostPath-style mount, label untouched =="
if out=$(pod 2>&1); then
  echo "RESULT: runs"
else
  echo "RESULT: DENIED"
  show_error "$out"
fi

echo
echo "== 2. container relabeled spc_t (custom SCC; rootful podman only) =="
if out=$(pod --security-opt label=type:spc_t 2>&1); then
  echo "RESULT: runs"
else
  echo "RESULT: DENIED"
  show_error "$out"
fi

echo
echo "== 2b. container with SELinux separation disabled (label=disable) =="
if out=$(pod --security-opt label=disable 2>&1); then
  echo "RESULT: runs"
else
  echo "RESULT: DENIED"
  show_error "$out"
fi

echo
echo "== 3. staged files relabeled container_file_t (:Z) =="
if out=$(podman run --rm --device /dev/kvm -v "$STAGE":/assets:ro,Z \
  "$IMAGE" \
  /assets/lib/ld-linux-x86-64.so.2 --library-path /assets/lib \
  /assets/qemu-system-x86_64 --version 2>&1); then
  echo "RESULT: runs (note: :Z relabels $STAGE on the host)"
else
  echo "RESULT: DENIED"
  show_error "$out"
fi

echo
echo "staged binary label now: $(label "$STAGE/qemu-system-x86_64")"
echo "inspect denials with: sudo ausearch -m avc -ts recent"
