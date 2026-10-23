package supplychain

import (
	"tijeri/internal/assets/discovery/repo"
)

type Router struct {
}

// RouteFlags represents the destinations a repository should be routed to for deeper scanning
type RouteFlags struct {
	SCA           bool
	ContainerScan bool
}

func (r *Router) RouteRepoSignal(signal repo.RepoSignalEvent) RouteFlags {
	flags := RouteFlags{}

	for _, eco := range signal.Ecosystems {
		if eco == "docker" {
			flags.ContainerScan = true
		}
		// We consider anything else known to the P1-1 ecosystem detector as SCA-eligible.
		if eco == "pypi" || eco == "npm" || eco == "go" || eco == "cargo" || eco == "rubygems" {
			flags.SCA = true
		}
	}

	return flags
}
