// Copyright 2016-2018, Pulumi Corporation.
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

//go:build !windows && !js
// +build !windows,!js

package cmdutil

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
)

// KillChildren calls os.Process.Kill() on every child process of `pid`'s, stoping after the first error (if any). It
// also only kills direct child process, not any children they may have.
func KillChildren(pid int) error {
	// A subprocess that was launched after calling `RegisterProcessGroup` below will
	// belong to a process group whose ID is the same as the PID. Passing the negation
	// of our PID (same as the PGID) sends a SIGKILL to all processes in our group.
	//
	// Relevant documentation: https://linux.die.net/man/2/kill
	// "If pid is less than -1, then sig is sent to every process in the
	// process group whose ID is -pid. "
	return syscall.Kill(-pid, syscall.SIGKILL)
}

// killProcessGroup sends SIGKILL to the process group for the given process.
//
// This is a helper function for TerminateProcessGroup;
// a Windows version with the same signature exists in child_windows.go.
func killProcessGroup(proc *os.Process) error {
	return KillChildren(proc.Pid)
}

// RegisterProcessGroup informs the OS that it needs to call `setpgid` on this
// child process. When it comes time to kill this process, we'll kill all processes
// in the same process group.
func RegisterProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func InterruptChildren(pid int) {
	err := syscall.Kill(-pid, syscall.SIGINT)
	contract.IgnoreError(err)
}
