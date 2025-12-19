package container

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ContainerResolver translates cgroup IDs to container identifiers
type ContainerResolver struct {
	cache map[uint64]string
	mu    sync.RWMutex
}

// NewContainerResolver creates a new container resolver
func NewContainerResolver() *ContainerResolver {
	return &ContainerResolver{
		cache: make(map[uint64]string),
	}
}

// ResolveCgroupID converts a cgroup ID to a container identifier
// Returns a string like "docker-1234abcd5678" or "container-name" or empty string if not found
func (r *ContainerResolver) ResolveCgroupID(cgroupID uint64) string {
	// Check cache first
	r.mu.RLock()
	if cached, ok := r.cache[cgroupID]; ok {
		r.mu.RUnlock()
		return cached
	}
	r.mu.RUnlock()

	// Try to resolve from cgroup filesystem
	resolved := r.resolveCgroupPath(cgroupID)

	// Cache the result (even if empty, to avoid repeated lookups)
	r.mu.Lock()
	r.cache[cgroupID] = resolved
	r.mu.Unlock()

	return resolved
}

// resolveCgroupPath attempts to find container ID from cgroup hierarchy
// Scans /sys/fs/cgroup for directories containing the cgroup ID
func (r *ContainerResolver) resolveCgroupPath(cgroupID uint64) string {
	// Try common cgroup paths
	cgroupPaths := []string{
		"/sys/fs/cgroup/docker",
		"/sys/fs/cgroup/cgroup.subtree_control",
		"/sys/fs/cgroup",
	}

	for _, basePath := range cgroupPaths {
		if result := r.searchCgroupDirectory(basePath, cgroupID); result != "" {
			return result
		}
	}

	// Fallback: try to find using cgroupfs (kernel 4.18+)
	if result := r.resolveByCgroupfsID(cgroupID); result != "" {
		return result
	}

	return ""
}

// searchCgroupDirectory recursively searches for the cgroup ID in directory structure
func (r *ContainerResolver) searchCgroupDirectory(path string, cgroupID uint64) string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if entry.IsDir() {
			fullPath := filepath.Join(path, entry.Name())

			// Check if this looks like a container ID
			if r.isValidContainerID(entry.Name()) {
				// Verify this directory contains the cgroup ID
				if r.cgroupIDInPath(fullPath, cgroupID) {
					return entry.Name()
				}
			}

			// Recurse into subdirectories (limit depth to 5)
			if result := r.searchCgroupDirectoryDepth(fullPath, cgroupID, 5); result != "" {
				return result
			}
		}
	}

	return ""
}

// searchCgroupDirectoryDepth recursively searches with depth limit
func (r *ContainerResolver) searchCgroupDirectoryDepth(path string, cgroupID uint64, depth int) string {
	if depth <= 0 {
		return ""
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return ""
	}

	for _, entry := range entries {
		if entry.IsDir() {
			fullPath := filepath.Join(path, entry.Name())

			// Check if this looks like a container ID
			if r.isValidContainerID(entry.Name()) {
				if r.cgroupIDInPath(fullPath, cgroupID) {
					return entry.Name()
				}
			}

			// Recurse
			if result := r.searchCgroupDirectoryDepth(fullPath, cgroupID, depth-1); result != "" {
				return result
			}
		}
	}

	return ""
}

// isValidContainerID checks if a directory name looks like a container ID
// Common patterns: 64-char hex (SHA256), 12-char hex (short SHA), or alphanumeric with dashes
func (r *ContainerResolver) isValidContainerID(name string) bool {
	// Docker full SHA: 64 hex characters
	if len(name) == 64 && isHexString(name) {
		return true
	}

	// Docker short SHA: 12 hex characters
	if len(name) == 12 && isHexString(name) {
		return true
	}

	// Container name: alphanumeric with dashes and underscores
	if len(name) > 0 && len(name) < 256 {
		for _, ch := range name {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.') {
				return false
			}
		}
		return true
	}

	return false
}

// cgroupIDInPath checks if a specific cgroup ID exists in a path's files
func (r *ContainerResolver) cgroupIDInPath(path string, cgroupID uint64) bool {
	// Try to find cgroup.id file (kernel 4.18+)
	cgroupIDFile := filepath.Join(path, "cgroup.id")
	if data, err := os.ReadFile(cgroupIDFile); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), fmt.Sprintf("%d", cgroupID)) {
				return true
			}
		}
	}

	// Try other cgroup files
	cgroupFiles := []string{
		"cgroup.procs",
		"cgroup.threads",
		"tasks",
	}

	for _, filename := range cgroupFiles {
		filePath := filepath.Join(path, filename)
		if data, err := os.ReadFile(filePath); err == nil {
			// Very basic check: if the file is not empty, assume it belongs to this cgroup
			if len(data) > 0 {
				return true
			}
		}
	}

	return false
}

// resolveByCgroupfsID uses cgroupfs ID attribute if available (kernel 4.18+)
func (r *ContainerResolver) resolveByCgroupfsID(cgroupID uint64) string {
	// Try to access cgroupfs stat for all processes
	// This is kernel 4.18+ feature
	procPath := "/proc"

	entries, err := os.ReadDir(procPath)
	if err != nil {
		return ""
	}

	cgroupIDStr := fmt.Sprintf("%d", cgroupID)

	for _, entry := range entries {
		// Only look at numeric directories (PIDs)
		if !entry.IsDir() || !isNumericDir(entry.Name()) {
			continue
		}

		cgroupPath := filepath.Join(procPath, entry.Name(), "cgroup")
		if data, err := os.ReadFile(cgroupPath); err == nil {
			if strings.Contains(string(data), cgroupIDStr) {
				// Found a process with this cgroup ID
				// Try to infer container from the cgroup path
				return r.extractContainerFromCgroupPath(string(data))
			}
		}
	}

	return ""
}

// extractContainerFromCgroupPath extracts container ID from /proc/[pid]/cgroup content
func (r *ContainerResolver) extractContainerFromCgroupPath(cgroupData string) string {
	lines := strings.Split(cgroupData, "\n")

	for _, line := range lines {
		// Format: 1:name=systemd:/docker/container_id/...
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			path := parts[len(parts)-1]

			// Extract container ID from path
			// Common patterns:
			// /docker/abc123def456...
			// /lxc/container-name
			// /cri-containerd/container-id

			if strings.Contains(path, "docker") {
				if id := extractIDFromPath(path, "docker"); id != "" {
					return "docker-" + id
				}
			} else if strings.Contains(path, "cri-containerd") {
				if id := extractIDFromPath(path, "cri-containerd"); id != "" {
					return "containerd-" + id
				}
			} else if strings.Contains(path, "lxc") {
				if id := extractIDFromPath(path, "lxc"); id != "" {
					return "lxc-" + id
				}
			}
		}
	}

	return ""
}

// extractIDFromPath extracts the container ID from a cgroup path
// e.g., "/docker/abc123def456/..." -> "abc123def456"
func extractIDFromPath(path, containerType string) string {
	parts := strings.Split(path, "/")

	for i, part := range parts {
		if part == containerType && i+1 < len(parts) {
			// Next part is usually the container ID
			id := parts[i+1]
			if id != "" {
				// Extract just the ID part (before any /), limit to reasonable length
				if idx := strings.Index(id, "/"); idx != -1 {
					id = id[:idx]
				}
				return id
			}
		}
	}

	return ""
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

// isNumericDir checks if a directory name is numeric (for PID matching)
func isNumericDir(name string) bool {
	_, err := strconv.ParseUint(name, 10, 32)
	return err == nil
}

// ClearCache clears the cached mappings
func (r *ContainerResolver) ClearCache() {
	r.mu.Lock()
	r.cache = make(map[uint64]string)
	r.mu.Unlock()
}

// GetCacheSize returns the current size of the cache
func (r *ContainerResolver) GetCacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}
