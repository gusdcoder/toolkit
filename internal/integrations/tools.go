package integrations

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"toolkit/internal/database"
)

// ToolInterface define a interface para ferramentas
type ToolInterface interface {
	Name() string
	Description() string
	Version() string
	IsInstalled() bool
	Install() error
	Execute(args []string) (string, error)
}

// ToolManager gerencia as ferramentas disponíveis
type ToolManager struct {
	tools map[string]ToolInterface
	mu    sync.RWMutex
	db    *database.DatabaseWrapper
}

// NewToolManager cria um novo gerenciador de ferramentas
func NewToolManager() *ToolManager {
	return &ToolManager{
		tools: make(map[string]ToolInterface),
	}
}

// NewToolManagerWithDB cria um novo gerenciador de ferramentas com banco de dados
func NewToolManagerWithDB(db *database.DatabaseWrapper, registerDefaults bool) *ToolManager {
	tm := &ToolManager{
		tools: make(map[string]ToolInterface),
		db:    db,
	}
	if registerDefaults {
		RegisterDefaultTools()
	}
	return tm
}

// RegisterTool registra uma nova ferramenta
func (tm *ToolManager) RegisterTool(name string, tool ToolInterface) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tools[name] = tool
}

// GetTool obtém uma ferramenta pelo nome
func (tm *ToolManager) GetTool(name string) (ToolInterface, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tool, exists := tm.tools[name]
	if !exists {
		return nil, fmt.Errorf("tool '%s' not found", name)
	}
	return tool, nil
}

// ListTools lista todas as ferramentas registradas
func (tm *ToolManager) ListTools() []string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	var names []string
	for name := range tm.tools {
		names = append(names, name)
	}
	return names
}

// RunTool executa uma ferramenta específica
func (tm *ToolManager) RunTool(ctx context.Context, name string, params map[string]interface{}) (interface{}, error) {
	tool, err := tm.GetTool(name)
	if err != nil {
		return nil, err
	}

	// Converter params para args
	var args []string
	for key, value := range params {
		args = append(args, fmt.Sprintf("--%s", key), fmt.Sprintf("%v", value))
	}

	result, err := tool.Execute(args)
	if err != nil {
		return nil, err
	}

	return result, nil
} // SimpleToolWrapper implementa ToolInterface para ferramentas simples de linha de comando
type SimpleToolWrapper struct {
	name        string
	description string
	command     string
}

// NewSimpleToolWrapper cria um wrapper para ferramentas simples
func NewSimpleToolWrapper(name, description, command string) *SimpleToolWrapper {
	return &SimpleToolWrapper{
		name:        name,
		description: description,
		command:     command,
	}
}

func (stw *SimpleToolWrapper) Name() string {
	return stw.name
}

func (stw *SimpleToolWrapper) Description() string {
	return stw.description
}

func (stw *SimpleToolWrapper) Version() string {
	cmd := exec.Command(stw.command, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(output))
}

func (stw *SimpleToolWrapper) IsInstalled() bool {
	_, err := exec.LookPath(stw.command)
	return err == nil
}

func (stw *SimpleToolWrapper) Install() error {
	return errors.New("manual installation required")
}

func (stw *SimpleToolWrapper) Execute(args []string) (string, error) {
	cmd := exec.Command(stw.command, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// Instância global do gerenciador de ferramentas
var GlobalToolManager = NewToolManager()

// RegisterDefaultTools registra as ferramentas padrão
func RegisterDefaultTools() {
	GlobalToolManager.RegisterTool("subfinder", NewSimpleToolWrapper("subfinder", "Subdomain discovery tool", "subfinder"))
	GlobalToolManager.RegisterTool("naabu", NewSimpleToolWrapper("naabu", "Port scanning tool", "naabu"))
	GlobalToolManager.RegisterTool("httpx", NewSimpleToolWrapper("httpx", "HTTP toolkit", "httpx"))
	GlobalToolManager.RegisterTool("nuclei", NewSimpleToolWrapper("nuclei", "Vulnerability scanner", "nuclei"))
}
