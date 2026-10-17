// SPDX-License-Identifier: Apache-2.0
package workbench

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Engine names are fixed by code. Requests never supply executable paths or
// shell fragments. Callers own fixed argument construction and target scope.
var assessmentEngines = map[string]bool{"nmap": true, "tshark": true, "foremost": true}

type boundedEngineOutput struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	overflow bool
}

func (w *boundedEngineOutput) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := w.limit - len(w.data)
	if len(data) > remaining {
		w.data = append(w.data, data[:remaining]...)
		w.overflow = true
		return remaining, fmt.Errorf("engine output limit reached")
	}
	w.data = append(w.data, data...)
	return len(data), nil
}

func runAuditEngine(ctx context.Context, executable string, args []string) ([]byte, error) {
	if !assessmentEngines[executable] {
		return nil, fmt.Errorf("engine is not supported for execution")
	}
	path, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed or not available on PATH", executable)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	stdout := &boundedEngineOutput{limit: MaxInput}
	stderr := &boundedEngineOutput{limit: 4096}
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = 2 * time.Second
	err = command.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s execution cancelled or reached its deadline", executable)
	}
	if stdout.overflow || stderr.overflow {
		return nil, fmt.Errorf("%s output exceeded its collection limit", executable)
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return nil, fmt.Errorf("%s exited with code %d", executable, exit.ExitCode())
		}
		return nil, fmt.Errorf("%s could not execute", executable)
	}
	return stdout.data, nil
}
