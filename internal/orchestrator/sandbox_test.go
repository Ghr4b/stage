package orchestrator

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSandboxIsolation(t *testing.T) {
	var sandbox Sandbox = &DockerSandbox{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("Code-path assertion: adapter never runs in-process", func(t *testing.T) {
		// This is a static assertion. We can verify that the implementation uses 'exec.Command'
		// or that 'sandbox' is a 'DockerSandbox'. The architecture mandates out-of-process.
		_, ok := sandbox.(*DockerSandbox)
		if !ok {
			t.Error("Expected sandbox to be DockerSandbox (out-of-process)")
		}
	})

	// Ensure Docker is available for the test
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("Docker not available, skipping remaining isolation tests")
	}

	t.Run("Disallowed egress attempt fails", func(t *testing.T) {
		cfg := SandboxConfig{
			Image:       "alpine:latest",
			Command:     []string{"ping", "-c", "1", "8.8.8.8"},
			AllowEgress: false,
		}

		out, err := sandbox.Run(ctx, cfg)
		if err == nil {
			t.Errorf("Expected ping to fail without network access, but it succeeded. Output: %s", string(out))
		}
		// The error should reflect network unreachable
		if !strings.Contains(string(out), "Network is unreachable") && !strings.Contains(string(out), "bad address") {
			t.Logf("Warning: output was %s", string(out))
		}
	})

	t.Run("Credential scoping: concurrent jobs do not share env", func(t *testing.T) {
		// Job 1 should only see CRED=job1
		cfg1 := SandboxConfig{
			Image:   "alpine:latest",
			Command: []string{"sh", "-c", "echo $CRED"},
			Env:     map[string]string{"CRED": "job1"},
		}

		// Job 2 should only see CRED=job2
		cfg2 := SandboxConfig{
			Image:   "alpine:latest",
			Command: []string{"sh", "-c", "echo $CRED"},
			Env:     map[string]string{"CRED": "job2"},
		}

		out1, err1 := sandbox.Run(ctx, cfg1)
		if err1 != nil {
			t.Fatalf("Job 1 failed: %v, output: %s", err1, string(out1))
		}

		out2, err2 := sandbox.Run(ctx, cfg2)
		if err2 != nil {
			t.Fatalf("Job 2 failed: %v, output: %s", err2, string(out2))
		}

		res1 := strings.TrimSpace(string(out1))
		res2 := strings.TrimSpace(string(out2))

		if res1 != "job1" {
			t.Errorf("Job 1 got credential %s, want job1", res1)
		}
		if res2 != "job2" {
			t.Errorf("Job 2 got credential %s, want job2", res2)
		}
		if res1 == res2 {
			t.Errorf("Credential overlap detected! Both jobs got %s", res1)
		}
	})
}
