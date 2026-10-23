package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const mebibyte = int64(1024 * 1024)

func scanWorkerCount() (int, error) {
	workers := runtime.GOMAXPROCS(0)
	if workers > 1 {
		workers--
	}

	reserveMB, err := positiveEnvInt("SCAN_RESERVED_MEMORY_MB", 512)
	if err != nil {
		return 0, err
	}
	perWorkerMB, err := positiveEnvInt("SCAN_MEMORY_PER_WORKER_MB", 768)
	if err != nil {
		return 0, err
	}
	if memoryLimit := containerMemoryLimit(); memoryLimit > 0 {
		reserve := int64(reserveMB) * mebibyte
		if quarter := memoryLimit / 4; quarter > reserve {
			reserve = quarter
		}
		memoryWorkers := int((memoryLimit - reserve) / (int64(perWorkerMB) * mebibyte))
		if memoryWorkers < 1 {
			memoryWorkers = 1
		}
		if memoryWorkers < workers {
			workers = memoryWorkers
		}
	}

	if maximum, set, err := optionalPositiveEnvInt("SCAN_MAX_WORKERS"); err != nil {
		return 0, err
	} else if set && maximum < workers {
		workers = maximum
	}
	if workers < 1 {
		workers = 1
	}
	return workers, nil
}

func positiveEnvInt(name string, fallback int) (int, error) {
	value, set, err := optionalPositiveEnvInt(name)
	if err != nil {
		return 0, err
	}
	if !set {
		return fallback, nil
	}
	return value, nil
}

func optionalPositiveEnvInt(name string) (int, bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0, false, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, false, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, true, nil
}

func containerMemoryLimit() int64 {
	for _, path := range []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(data))
		if value == "max" {
			return 0
		}
		limit, err := strconv.ParseInt(value, 10, 64)
		if err == nil && limit > 0 && limit < (1<<60) {
			return limit
		}
	}
	return 0
}
