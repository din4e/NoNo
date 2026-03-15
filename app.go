package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/nono/internal/config"
	"github.com/nono/internal/injector"
	"github.com/nono/internal/scanner"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the main application struct for Wails bindings
type App struct {
	ctx     context.Context
	scan    *scanner.Scanner
	config  *config.AppConfig
}

// NewApp creates a new App instance
func NewApp() *App {
	return &App{
		config: config.DefaultConfig(),
	}
}

// startup is called when the app starts
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// SelectDirectory opens a directory selection dialog
func (a *App) SelectDirectory() (string, error) {
	return wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select Directory to Scan",
	})
}

// SelectPEFile opens a PE file selection dialog
func (a *App) SelectPEFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select PE File",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Executable Files (*.exe, *.dll)", Pattern: "*.exe;*.dll"},
		},
	})
}

// SelectShellcodeFile opens a shellcode file selection dialog
func (a *App) SelectShellcodeFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select Shellcode File",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Binary Files (*.bin)", Pattern: "*.bin"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
}

// StartScan starts a directory scan with the given configuration
func (a *App) StartScan(cfg config.ScanConfigJSON) error {
	scanConfig := scanner.ScanConfig{
		Directory:    cfg.Directory,
		MinSize:      cfg.MinSize,
		MaxSize:      cfg.MaxSize,
		Architecture: cfg.Architecture,
		Extensions:   cfg.Extensions,
		Workers:      cfg.Workers,
		SignFilter:   cfg.SignFilter,
		ShowImports:  cfg.ShowImports,
	}

	// Process extensions
	for i := range scanConfig.Extensions {
		scanConfig.Extensions[i] = strings.TrimSpace(strings.ToLower(scanConfig.Extensions[i]))
		if !strings.HasPrefix(scanConfig.Extensions[i], ".") {
			scanConfig.Extensions[i] = "." + scanConfig.Extensions[i]
		}
	}

	if len(scanConfig.Extensions) == 0 {
		scanConfig.Extensions = []string{".exe"}
	}

	if scanConfig.Workers <= 0 {
		scanConfig.Workers = runtime.NumCPU()
	}

	a.scan = scanner.NewScanner(scanConfig)

	a.scan.OnProgress(func(p scanner.ScanProgress) {
		wailsRuntime.EventsEmit(a.ctx, "scan:progress", p)
	})

	a.scan.OnResult(func(f scanner.FileInfo) {
		wailsRuntime.EventsEmit(a.ctx, "scan:result", f)
	})

	go func() {
		defer wailsRuntime.EventsEmit(a.ctx, "scan:complete", a.scan.GetResults())
		if err := a.scan.Run(); err != nil {
			wailsRuntime.EventsEmit(a.ctx, "scan:error", err.Error())
		}
	}()

	return nil
}

// StopScan stops the current scan
func (a *App) StopScan() {
	if a.scan != nil {
		a.scan.Stop()
	}
}

// GetScanProgress returns the current scan progress
func (a *App) GetScanProgress() scanner.ScanProgress {
	if a.scan == nil {
		return scanner.ScanProgress{}
	}
	return a.scan.GetProgress()
}

// GetScanResults returns all scan results
func (a *App) GetScanResults() []scanner.FileInfo {
	if a.scan == nil {
		return []scanner.FileInfo{}
	}
	return a.scan.GetResults()
}

// GetPEInfo returns detailed information about a PE file
func (a *App) GetPEInfo(path string) (*config.PEInfo, error) {
	info := &config.PEInfo{Path: path}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}
	info.Size = fileInfo.Size()

	arch, err := scanner.GetFileArchitecture(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get architecture: %w", err)
	}
	info.Architecture = arch

	// Check if DLL by extension
	ext := strings.ToLower(filepath.Ext(path))
	info.IsDLL = ext == ".dll"

	isSigned, signerInfo := scanner.CheckDigitalSignature(path)
	info.IsSigned = isSigned
	info.SignerInfo = signerInfo

	imports, err := scanner.GetImportTable(path)
	if err == nil {
		info.ImportedDLLs = make([]config.ImportDLLInfo, len(imports))
		for i, imp := range imports {
			info.ImportedDLLs[i] = config.ImportDLLInfo{
				DLLName:   imp.DLLName,
				Functions: imp.Functions,
			}
		}
		info.ImportCount = scanner.CountTotalImports(imports)
	}

	return info, nil
}

// Inject performs code injection
func (a *App) Inject(cfg config.InjectConfigJSON) (*injector.Result, error) {
	var method injector.Method
	switch strings.ToLower(cfg.Method) {
	case "function":
		method = injector.MethodFunction
	case "entrypoint":
		method = injector.MethodEntrypoint
	case "tlsinject":
		method = injector.MethodTLSInject
	case "eat":
		method = injector.MethodEAT
	default:
		return nil, fmt.Errorf("unknown injection method: %s", cfg.Method)
	}

	options := injector.Options{
		Method:      method,
		PreserveSig: cfg.PreserveSig,
		FuncName:    cfg.FuncName,
		Backup:      cfg.Backup,
	}

	inj := injector.NewInjector(options)
	return inj.Inject(cfg.PEPath, cfg.ShellcodePath)
}

// GetDefaultConfig returns the default configuration
func (a *App) GetDefaultConfig() *config.AppConfig {
	return a.config
}

// TemplateInfo holds information about a shellcode template
type TemplateInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Description string `json:"description"`
}

// GetTemplates returns a list of available shellcode templates
func (a *App) GetTemplates() []TemplateInfo {
	var templates []TemplateInfo

	// Try multiple locations to find templates
	searchDirs := []string{}

	// 1. Current working directory
	if wd, err := os.Getwd(); err == nil {
		searchDirs = append(searchDirs, wd)
	}

	// 2. Executable directory
	if exePath, err := os.Executable(); err == nil {
		searchDirs = append(searchDirs, filepath.Dir(exePath))
	}

	// Search for templates in all directories
	foundTemplates := make(map[string]bool)
	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			if strings.HasPrefix(name, "template_") && !foundTemplates[name] {
				foundTemplates[name] = true

				info, err := entry.Info()
				if err != nil {
					continue
				}

				desc := "Custom shellcode template"
				if name == "template_0" {
					desc = "MessageBox test shellcode"
				} else if name == "template_1" {
					desc = "File reader shellcode (reads AAAA.bin)"
				}

				templates = append(templates, TemplateInfo{
					Name:        name,
					Path:        filepath.Join(dir, name),
					Size:        info.Size(),
					Description: desc,
				})
			}
		}
	}

	// Return empty slice if no templates found (don't return error)
	return templates
}

// GetAppDir returns the application directory
func (a *App) GetAppDir() (string, error) {
	return os.Getwd()
}
