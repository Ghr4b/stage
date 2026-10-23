package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// RunCLIScanner locates a binary by name, executes it with the given arguments,
// and returns its stdout output. It handles the common patterns across all
// scanner adapters:
//   - Binary lookup via PATH
//   - Working directory for project-root scanners
//   - Environment variable injection (e.g., cloud credentials)
//   - Exit code 1 with output = success (used by trivy/grype when vulns found)
func RunCLIScanner(ctx context.Context, binName string, args []string, env map[string]string, workDir string) ([]byte, error) {
	binPath, err := exec.LookPath(binName)
	if nil != err {
		return nil, fmt.Errorf("%s not found in PATH: %w", binName, err)
	}

	cmd := exec.CommandContext(ctx, binPath, args...)

	if workDir != "" {
		cmd.Dir = workDir
	}

	if len(env) > 0 {
		cmd.Env = mergeEnv(env)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Many scanners return exit code 1 when findings exist — that's expected
			if stdout.Len() > 0 {
				return stdout.Bytes(), nil
			}
			return nil, fmt.Errorf("%s failed (exit %d): %s", binName, exitErr.ExitCode(), stderr.String())
		}
		return nil, fmt.Errorf("%s failed: %w", binName, err)
	}

	return stdout.Bytes(), nil
}

// mergeEnv creates an environment slice inheriting the current process environment
// and overlaying the provided key-value pairs.
func mergeEnv(extra map[string]string) []string {
	base := environ()
	for k, v := range extra {
		found := false
		for i, e := range base {
			if len(e) > len(k)+1 && e[:len(k)+1] == k+"=" {
				base[i] = k + "=" + v
				found = true
				break
			}
		}
		if !found {
			base = append(base, k+"="+v)
		}
	}
	return base
}

// environ returns a copy of the current process environment variables.
// Extracted for testability.
var environ = func() []string {
	return environImpl()
}

func environImpl() []string {
	cmd := exec.Command("env")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	lines := splitLines(out)
	return lines
}

func splitLines(data []byte) []string {
	var result []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := data[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			result = append(result, string(line))
			start = i + 1
		}
	}
	if start < len(data) {
		result = append(result, string(data[start:]))
	}
	return result
}
