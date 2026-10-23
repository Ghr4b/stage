package orchestrator

import (
	"context"
	"fmt"
	"os/exec"
)

// SandboxConfig defines the parameters for an isolated execution environment.
type SandboxConfig struct {
	Image       string
	Command     []string
	Env         map[string]string
	AllowEgress bool // Should default to false for least privilege
}

// Sandbox represents a runtime wrapper ensuring code runs out-of-process
// and is isolated.
type Sandbox interface {
	Run(ctx context.Context, config SandboxConfig) ([]byte, error)
}

// DockerSandbox implements the Sandbox interface using Docker for isolation.
// This ensures adapters never run in-process or as ambient host subprocesses.
type DockerSandbox struct{}

func (d *DockerSandbox) Run(ctx context.Context, config SandboxConfig) ([]byte, error) {
	// Base command
	args := []string{"run", "--rm"}

	// Egress control via network settings
	if !config.AllowEgress {
		args = append(args, "--network", "none")
	}

	// Scoped credential injection via environment variables.
	// (In a real deployment, this might use tmpfs secrets to avoid env leakage,
	// but env vars scoped strictly to the container are isolated between concurrent runs).
	for k, v := range config.Env {
		args = append(args, "-e", fmt.Sprintf("%s=%s", k, v))
	}

	// Image and command
	args = append(args, config.Image)
	args = append(args, config.Command...)

	cmd := exec.CommandContext(ctx, "docker", args...)
	return cmd.CombinedOutput()
}
