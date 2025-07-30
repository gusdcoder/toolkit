package scan

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type model struct {
	// For this simple example, we have no state.
}

func (m model) Init() tea.Cmd {
	// Just start listening for keyboard input.
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) View() string {
	return "Hello, World! This is the interactive scan UI. Press 'q' to quit."
}

func Start() error {
	p := tea.NewProgram(model{})
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("could not start interactive scan UI: %w", err)
	}
	return nil
}
