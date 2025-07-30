package workspace

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WorkspaceInfo contains metadata about a workspace
type WorkspaceInfo struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

// Manager handles workspace operations
type Manager struct {
	basePath    string
	configPath  string
	currentPath string
}

// NewManager creates a new workspace manager
func NewManager() (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	basePath := filepath.Join(homeDir, "Documents", "billy")
	configPath := filepath.Join(basePath, ".config")
	currentPath := filepath.Join(configPath, "current_workspace")

	// Ensure base directory exists
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base workspace directory: %w", err)
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &Manager{
		basePath:    basePath,
		configPath:  configPath,
		currentPath: currentPath,
	}, nil
}

// CreateWorkspace creates a new workspace
func (m *Manager) CreateWorkspace(name string) error {
	workspacePath := filepath.Join(m.basePath, name)

	// Check if workspace already exists
	if _, err := os.Stat(workspacePath); !os.IsNotExist(err) {
		return fmt.Errorf("workspace '%s' already exists", name)
	}

	// Create workspace directory
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Create subdirectories
	subdirs := []string{
		"scans",
		"results",
		"reports",
		"configs",
		"data",
		"logs",
	}

	for _, subdir := range subdirs {
		subdirPath := filepath.Join(workspacePath, subdir)
		if err := os.MkdirAll(subdirPath, 0755); err != nil {
			return fmt.Errorf("failed to create subdirectory '%s': %w", subdir, err)
		}
	}

	// Create workspace info file
	info := WorkspaceInfo{
		Name:      name,
		Path:      workspacePath,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
	}

	infoPath := filepath.Join(workspacePath, ".workspace_info.json")
	if err := m.saveWorkspaceInfo(infoPath, &info); err != nil {
		return fmt.Errorf("failed to save workspace info: %w", err)
	}

	// Create default config file
	defaultConfig := map[string]interface{}{
		"workspace": map[string]interface{}{
			"name":        name,
			"description": fmt.Sprintf("Reconnaissance workspace: %s", name),
			"created_at":  info.CreatedAt.Format(time.RFC3339),
		},
		"scan": map[string]interface{}{
			"threads":    50,
			"timeout":    30,
			"rate_limit": 100,
			"output_dir": "./results",
		},
		"tools": map[string]interface{}{
			"subfinder": map[string]interface{}{
				"enabled":   true,
				"threads":   10,
				"timeout":   30,
				"silent":    true,
				"recursive": false,
			},
			"naabu": map[string]interface{}{
				"enabled":   true,
				"top_ports": 1000,
				"threads":   25,
				"timeout":   5,
				"verify":    true,
			},
			"httpx": map[string]interface{}{
				"enabled":          true,
				"threads":          50,
				"timeout":          10,
				"follow_redirects": true,
				"status_code":      true,
				"content_length":   true,
			},
			"nuclei": map[string]interface{}{
				"enabled":  true,
				"threads":  25,
				"timeout":  5,
				"severity": []string{"critical", "high", "medium"},
				"tags":     []string{"cve", "oast", "tech"},
			},
		},
	}

	configPath := filepath.Join(workspacePath, "configs", "config.yaml")
	if err := m.saveConfig(configPath, defaultConfig); err != nil {
		return fmt.Errorf("failed to create default config: %w", err)
	}

	// Create README
	readmePath := filepath.Join(workspacePath, "README.md")
	readme := fmt.Sprintf(`# Workspace: %s

This is a reconnaissance workspace created on %s.

## Directory Structure

- **scans/**: Raw scan outputs
- **results/**: Processed results and data
- **reports/**: Generated reports
- **configs/**: Configuration files
- **data/**: Database and temporary files
- **logs/**: Application logs

## Quick Start

1. Switch to this workspace:
   `+"`recon workspace switch %s`"+`

2. Run a basic scan:
   `+"`recon scan -d example.com`"+`

3. Run interactive mode:
   `+"`recon scan --interactive`"+`

## Configuration

Edit `+"`configs/config.yaml`"+` to customize scan settings for this workspace.
`, name, info.CreatedAt.Format("2006-01-02 15:04:05"), name)

	if err := os.WriteFile(readmePath, []byte(readme), 0644); err != nil {
		return fmt.Errorf("failed to create README: %w", err)
	}

	return nil
}

// ListWorkspaces returns all available workspaces
func (m *Manager) ListWorkspaces() ([]WorkspaceInfo, error) {
	entries, err := os.ReadDir(m.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read workspace directory: %w", err)
	}

	var workspaces []WorkspaceInfo

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == ".config" {
			continue
		}

		workspacePath := filepath.Join(m.basePath, entry.Name())
		infoPath := filepath.Join(workspacePath, ".workspace_info.json")

		info, err := m.loadWorkspaceInfo(infoPath)
		if err != nil {
			// If no info file, create basic info from directory
			info = &WorkspaceInfo{
				Name:      entry.Name(),
				Path:      workspacePath,
				CreatedAt: time.Now(),
			}
		}

		workspaces = append(workspaces, *info)
	}

	return workspaces, nil
}

// SwitchWorkspace switches to the specified workspace
func (m *Manager) SwitchWorkspace(name string) error {
	workspacePath := filepath.Join(m.basePath, name)

	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return fmt.Errorf("workspace '%s' does not exist", name)
	}

	// Update last used time
	infoPath := filepath.Join(workspacePath, ".workspace_info.json")
	info, err := m.loadWorkspaceInfo(infoPath)
	if err == nil {
		info.LastUsed = time.Now()
		m.saveWorkspaceInfo(infoPath, info)
	}

	// Save current workspace
	if err := os.WriteFile(m.currentPath, []byte(name), 0644); err != nil {
		return fmt.Errorf("failed to save current workspace: %w", err)
	}

	return nil
}

// GetCurrentWorkspace returns the currently active workspace
func (m *Manager) GetCurrentWorkspace() (string, error) {
	data, err := os.ReadFile(m.currentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No current workspace set
		}
		return "", fmt.Errorf("failed to read current workspace: %w", err)
	}

	return string(data), nil
}

// DeleteWorkspace deletes the specified workspace
func (m *Manager) DeleteWorkspace(name string) error {
	workspacePath := filepath.Join(m.basePath, name)

	// Check if workspace exists
	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return fmt.Errorf("workspace '%s' does not exist", name)
	}

	// Check if it's the current workspace
	current, _ := m.GetCurrentWorkspace()
	if current == name {
		// Clear current workspace
		os.Remove(m.currentPath)
	}

	// Remove workspace directory
	if err := os.RemoveAll(workspacePath); err != nil {
		return fmt.Errorf("failed to delete workspace directory: %w", err)
	}

	return nil
}

// GetWorkspacePath returns the full path to a workspace
func (m *Manager) GetWorkspacePath(name string) string {
	return filepath.Join(m.basePath, name)
}

// GetCurrentWorkspacePath returns the path to the current workspace
func (m *Manager) GetCurrentWorkspacePath() (string, error) {
	current, err := m.GetCurrentWorkspace()
	if err != nil {
		return "", err
	}

	if current == "" {
		return "", fmt.Errorf("no current workspace set")
	}

	return m.GetWorkspacePath(current), nil
}

// saveWorkspaceInfo saves workspace info to file
func (m *Manager) saveWorkspaceInfo(path string, info *WorkspaceInfo) error {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// loadWorkspaceInfo loads workspace info from file
func (m *Manager) loadWorkspaceInfo(path string) (*WorkspaceInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var info WorkspaceInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// saveConfig saves configuration to YAML file
func (m *Manager) saveConfig(path string, config map[string]interface{}) error {
	// For now, save as JSON. Can be upgraded to YAML later
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
