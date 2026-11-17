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

// Package cpio writes the newc cpio format that Linux unpacks as an
// initramfs. Only the pieces the spike needs are implemented: files,
// directories and the trailer.
package cpio

import (
	"fmt"
	"io"
)

const newcMagic = "070701"

// Writer writes entries to an underlying stream.
type Writer struct {
	w   io.Writer
	ino uint32
}

// NewWriter returns a Writer that emits to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Directory writes an empty directory entry. The name must end in "/".
func (w *Writer) Directory(name string) error {
	return w.entry(name, 0o040755, nil)
}

// File writes a regular file entry with the given mode and contents.
func (w *Writer) File(name string, mode uint32, data []byte) error {
	return w.entry(name, 0o0100000|mode, data)
}

// Close writes the trailer. The archive is padded so the kernel can read it
// back to back with more data.
func (w *Writer) Close() error {
	return w.entry("TRAILER!!!", 0, nil)
}

func (w *Writer) entry(name string, mode uint32, data []byte) error {
	w.ino++
	hdr := []uint32{
		w.ino,                 // c_ino
		mode,                  // c_mode
		0,                     // c_uid
		0,                     // c_gid
		1,                     // c_nlink
		0,                     // c_mtime
		uint32(len(data)),     // c_filesize
		0,                     // c_devmajor
		0,                     // c_devminor
		0,                     // c_rdevmajor
		0,                     // c_rdevminor
		uint32(len(name) + 1), // c_namesize, counting the trailing NUL
		0,                     // c_check
	}
	if _, err := fmt.Fprintf(w.w, "%s", newcMagic); err != nil {
		return err
	}
	for _, f := range hdr {
		if _, err := fmt.Fprintf(w.w, "%08x", f); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w.w, "%s\x00", name); err != nil {
		return err
	}
	// The header plus name is padded to a multiple of four.
	if err := pad(w.w, 110+len(name)+1); err != nil {
		return err
	}
	if _, err := w.w.Write(data); err != nil {
		return err
	}
	return pad(w.w, len(data))
}

// pad writes NUL bytes until the bytes written since the start of the entry
// reach a multiple of four. size is the byte count already written.
func pad(w io.Writer, size int) error {
	if r := size % 4; r != 0 {
		if _, err := w.Write(make([]byte, 4-r)); err != nil {
			return err
		}
	}
	return nil
}
