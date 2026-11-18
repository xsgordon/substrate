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

// Package qmp is a minimal QEMU Machine Protocol client over a unix socket,
// for driving the QEMU microVM backend. It covers the commands the worker
// needs: run-state control, the ignore-shared migration that snapshots device
// state, and migrate-incoming for restore. Async events that arrive while a
// command result is being read are skipped.
package qmp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Conn is a connected QMP socket.
type Conn struct {
	conn *net.UnixConn
	r    *bufio.Reader
	id   int
}

// Dial connects to the QMP socket, reads the greeting and negotiates
// capabilities.
func Dial(path string) (*Conn, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	c := &Conn{conn: conn, r: bufio.NewReader(conn)}
	var greeting struct {
		QMP any `json:"QMP"`
	}
	if err := c.readMsg(&greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("qmp greeting: %w", err)
	}
	if _, err := c.Command("qmp_capabilities", nil); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

// Close closes the socket.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// Command sends one QMP command and returns its "return" member.
func (c *Conn) Command(execute string, args map[string]any) (json.RawMessage, error) {
	c.id++
	req := struct {
		Execute   string         `json:"execute"`
		Arguments map[string]any `json:"arguments,omitempty"`
		ID        int            `json:"id,omitempty"`
	}{Execute: execute, Arguments: args, ID: c.id}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if _, err := c.conn.Write(data); err != nil {
		return nil, err
	}
	// Command replies are prompt; a hung read must not hold the actor's
	// lifecycle lock forever.
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	for {
		var msg struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			ID    int    `json:"id"`
			Event string `json:"event"`
		}
		if err := c.readMsg(&msg); err != nil {
			return nil, err
		}
		if msg.Event != "" {
			continue
		}
		if msg.ID != c.id {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("qmp %s: %s", msg.Error.Class, msg.Error.Desc)
		}
		return msg.Return, nil
	}
}

// readMsg reads one JSON message from the socket and decodes it into v.
func (c *Conn) readMsg(v any) error {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(line) == 0 {
		return errors.New("qmp: empty message")
	}
	return json.Unmarshal(line, v)
}

// Stop pauses the VM. It is idempotent.
func (c *Conn) Stop() error {
	_, err := c.Command("stop", nil)
	return err
}

// Cont resumes the VM.
func (c *Conn) Cont() error {
	_, err := c.Command("cont", nil)
	return err
}

// QueryStatus reports the VM run state.
func (c *Conn) QueryStatus() (string, error) {
	raw, err := c.Command("query-status", nil)
	if err != nil {
		return "", err
	}
	var s struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s.Status, nil
}

// CPUCount returns the vCPU count, for recording in a snapshot.
func (c *Conn) CPUCount() (int, error) {
	raw, err := c.Command("query-cpus-fast", nil)
	if err != nil {
		return 0, err
	}
	var cpus []struct {
		Index int `json:"index"`
	}
	if err := json.Unmarshal(raw, &cpus); err != nil {
		return 0, err
	}
	return len(cpus), nil
}

// MigrateStats is the part of query-migrate the worker reports.
type MigrateStats struct {
	Status         string `json:"status"`
	TotalTimeMS    int64  `json:"total-time"`
	RamTransferred int64  `json:"transferred"`
}

// SetIgnoreShared turns on the x-ignore-shared migration capability, which
// skips shared memory-backend regions. Both ends of the migration need it:
// with it, the stream carries device state only, and guest RAM travels as
// the memory-backend file itself.
func (c *Conn) SetIgnoreShared() error {
	_, err := c.Command("migrate-set-capabilities", map[string]any{
		"capabilities": []map[string]any{{"capability": "x-ignore-shared", "state": true}},
	})
	return err
}

// Migrate starts an outgoing migration to uri.
func (c *Conn) Migrate(uri string) error {
	_, err := c.Command("migrate", map[string]any{"uri": uri})
	return err
}

// MigrateIncoming starts an incoming migration from uri. The VM must have
// been launched with -incoming defer.
func (c *Conn) MigrateIncoming(uri string) error {
	_, err := c.Command("migrate-incoming", map[string]any{"uri": uri})
	return err
}

// WaitMigrateCompleted polls query-migrate until the migration reaches a
// terminal state.
func (c *Conn) WaitMigrateCompleted() (*MigrateStats, error) {
	deadline := time.Now().Add(120 * time.Second)
	for {
		raw, err := c.Command("query-migrate", nil)
		if err != nil {
			return nil, err
		}
		var s struct {
			MigrateStats
			Ram *MigrateStats `json:"ram"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		switch s.Status {
		case "completed":
			out := s.MigrateStats
			if s.Ram != nil {
				out.RamTransferred = s.Ram.RamTransferred
			}
			return &out, nil
		case "failed", "cancelled":
			return nil, fmt.Errorf("migration %s", s.Status)
		case "":
			// query-migrate returns null before any migration ran.
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("migration stuck in %s", s.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
