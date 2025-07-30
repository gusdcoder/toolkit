package recon

import (
	"fmt"
	"strings"

	"toolkit/internal/workspace"

	"github.com/spf13/cobra"
)

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage reconnaissance workspaces",
	Long: `Manage workspaces for organizing reconnaissance projects.
Each workspace contains its own scans, results, and configuration.`,
}

var createWorkspaceCmd = &cobra.Command{
	Use:   "create [workspace-name]",
	Short: "Create a new workspace",
	Long:  `Create a new workspace with the specified name`,
	Args:  cobra.ExactArgs(1),
	RunE:  runCreateWorkspace,
}

var listWorkspacesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all workspaces",
	Long:  `List all available workspaces`,
	RunE:  runListWorkspaces,
}

var switchWorkspaceCmd = &cobra.Command{
	Use:   "switch [workspace-name]",
	Short: "Switch to a workspace",
	Long:  `Switch to the specified workspace`,
	Args:  cobra.ExactArgs(1),
	RunE:  runSwitchWorkspace,
}

var deleteWorkspaceCmd = &cobra.Command{
	Use:   "delete [workspace-name]",
	Short: "Delete a workspace",
	Long:  `Delete the specified workspace and all its data`,
	Args:  cobra.ExactArgs(1),
	RunE:  runDeleteWorkspace,
}

var currentWorkspaceCmd = &cobra.Command{
	Use:   "current",
	Short: "Show current workspace",
	Long:  `Show the currently active workspace`,
	RunE:  runCurrentWorkspace,
}

func init() {
	rootCmd.AddCommand(workspaceCmd)
	workspaceCmd.AddCommand(createWorkspaceCmd)
	workspaceCmd.AddCommand(listWorkspacesCmd)
	workspaceCmd.AddCommand(switchWorkspaceCmd)
	workspaceCmd.AddCommand(deleteWorkspaceCmd)
	workspaceCmd.AddCommand(currentWorkspaceCmd)
}

func runCreateWorkspace(cmd *cobra.Command, args []string) error {
	workspaceName := args[0]

	// Validate workspace name
	if err := validateWorkspaceName(workspaceName); err != nil {
		return err
	}

	ws, err := workspace.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	if err := ws.CreateWorkspace(workspaceName); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	fmt.Printf("✅ Workspace '%s' created successfully\n", workspaceName)
	fmt.Printf("📁 Location: %s\n", ws.GetWorkspacePath(workspaceName))

	// Switch to the new workspace
	if err := ws.SwitchWorkspace(workspaceName); err != nil {
		fmt.Printf("⚠️  Warning: Created workspace but failed to switch to it: %v\n", err)
	} else {
		fmt.Printf("🔄 Switched to workspace '%s'\n", workspaceName)
	}

	return nil
}

func runListWorkspaces(cmd *cobra.Command, args []string) error {
	ws, err := workspace.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	workspaces, err := ws.ListWorkspaces()
	if err != nil {
		return fmt.Errorf("failed to list workspaces: %w", err)
	}

	current, _ := ws.GetCurrentWorkspace()

	fmt.Println("📋 Available Workspaces:")
	fmt.Println()

	if len(workspaces) == 0 {
		fmt.Println("   No workspaces found. Create one with: recon workspace create <name>")
		return nil
	}

	for _, w := range workspaces {
		indicator := "  "
		if w.Name == current {
			indicator = "▶️"
		}

		fmt.Printf("%s %s\n", indicator, w.Name)
		fmt.Printf("   📁 %s\n", w.Path)
		fmt.Printf("   📅 Created: %s\n", w.CreatedAt.Format("2006-01-02 15:04:05"))
		if !w.LastUsed.IsZero() {
			fmt.Printf("   🕒 Last used: %s\n", w.LastUsed.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}

	return nil
}

func runSwitchWorkspace(cmd *cobra.Command, args []string) error {
	workspaceName := args[0]

	ws, err := workspace.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	if err := ws.SwitchWorkspace(workspaceName); err != nil {
		return fmt.Errorf("failed to switch workspace: %w", err)
	}

	fmt.Printf("🔄 Switched to workspace '%s'\n", workspaceName)
	fmt.Printf("📁 Location: %s\n", ws.GetWorkspacePath(workspaceName))

	return nil
}

func runDeleteWorkspace(cmd *cobra.Command, args []string) error {
	workspaceName := args[0]

	ws, err := workspace.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	// Confirm deletion
	fmt.Printf("⚠️  Are you sure you want to delete workspace '%s'? (y/N): ", workspaceName)
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
		fmt.Println("❌ Deletion cancelled")
		return nil
	}

	if err := ws.DeleteWorkspace(workspaceName); err != nil {
		return fmt.Errorf("failed to delete workspace: %w", err)
	}

	fmt.Printf("🗑️  Workspace '%s' deleted successfully\n", workspaceName)

	return nil
}

func runCurrentWorkspace(cmd *cobra.Command, args []string) error {
	ws, err := workspace.NewManager()
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	current, err := ws.GetCurrentWorkspace()
	if err != nil {
		return fmt.Errorf("failed to get current workspace: %w", err)
	}

	if current == "" {
		fmt.Println("❌ No workspace is currently active")
		fmt.Println("💡 Create a workspace with: recon workspace create <name>")
		return nil
	}

	fmt.Printf("📁 Current workspace: %s\n", current)
	fmt.Printf("🗂️  Location: %s\n", ws.GetWorkspacePath(current))

	return nil
}

func validateWorkspaceName(name string) error {
	if name == "" {
		return fmt.Errorf("workspace name cannot be empty")
	}

	if len(name) > 50 {
		return fmt.Errorf("workspace name cannot be longer than 50 characters")
	}

	// Check for invalid characters
	invalidChars := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range invalidChars {
		if strings.Contains(name, char) {
			return fmt.Errorf("workspace name cannot contain '%s'", char)
		}
	}

	return nil
}
