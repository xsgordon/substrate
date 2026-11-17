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

// Package qmp is a minimal QEMU Machine Protocol client over a unix socket.
// It covers the commands the snapshot spike needs, including fd passing for
// netdev_add, which net/http cannot do because it cannot attach SCM_RIGHTS.
package qmp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
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
	if err := c.readMsg(&greeting, 0); err != nil {
		conn.Close()
		return nil, fmt.Errorf("greeting: %w", err)
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

// Command sends one QMP command and returns its "return" member. Events
// that arrive while waiting are skipped.
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
	return c.readResult(c.id)
}

// GetFD passes fd to QEMU and names it fdname, for use by later commands
// such as netdev_add. The message and the SCM_RIGHTS control data must go
// out in one sendmsg, or QEMU can read the command without the fd.
func (c *Conn) GetFD(fdname string, fd int) error {
	c.id++
	req := struct {
		Execute   string         `json:"execute"`
		Arguments map[string]any `json:"arguments"`
		ID        int            `json:"id"`
	}{Execute: "getfd", Arguments: map[string]any{"fdname": fdname}, ID: c.id}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if _, _, err := c.conn.WriteMsgUnix(data, unix.UnixRights(fd), nil); err != nil {
		return err
	}
	_, err = c.readResult(c.id)
	return err
}

// readResult reads messages until the reply with the wanted id arrives.
func (c *Conn) readResult(id int) (json.RawMessage, error) {
	for {
		var msg struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			ID int `json:"id"`
		}
		if err := c.readMsg(&msg, id); err != nil {
			return nil, err
		}
		if msg.ID != id {
			continue
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("qmp %s: %s", msg.Error.Class, msg.Error.Desc)
		}
		return msg.Return, nil
	}
}

// readMsg reads one JSON message from the socket and decodes it into v.
// A deadline of zero waits indefinitely.
func (c *Conn) readMsg(v any, id int) error {
	if id != 0 {
		// Responses to a specific command are prompt.
		c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		defer c.conn.SetReadDeadline(time.Time{})
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return err
	}
	if len(line) == 0 {
		return errors.New("qmp: empty message")
	}
	return json.Unmarshal(line, v)
}

// Status is the reply to query-status.
type Status struct {
	Status  string `json:"status"`
	Running bool   `json:"running"`
}

// QueryStatus reports the VM run state.
func (c *Conn) QueryStatus() (*Status, error) {
	raw, err := c.Command("query-status", nil)
	if err != nil {
		return nil, err
	}
	var s Status
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
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

// MigrateStats is the part of query-migrate the spike reports.
type MigrateStats struct {
	Status      string `json:"status"`
	TotalTimeMS int64  `json:"total-time"`
	Ram         *struct {
		TotalBytes      int64 `json:"total"`
		TransferredByte int64 `json:"transferred"`
	} `json:"ram"`
}

// QueryMigrate reports migration progress.
func (c *Conn) QueryMigrate() (*MigrateStats, error) {
	raw, err := c.Command("query-migrate", nil)
	if err != nil {
		return nil, err
	}
	var s MigrateStats
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return &s, nil
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
		s, err := c.QueryMigrate()
		if err != nil {
			return nil, err
		}
		switch s.Status {
		case "completed":
			return s, nil
		case "failed", "cancelled":
			return s, fmt.Errorf("migration %s", s.Status)
		}
		if time.Now().After(deadline) {
			return s, fmt.Errorf("migration stuck in %s", s.Status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
