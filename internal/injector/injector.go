// Package injector provides PE code injection functionality
package injector

import (
	"fmt"
	"os"
)

// Method represents the injection method
type Method string

const (
	MethodFunction    Method = "function"    // Function patching
	MethodEntrypoint  Method = "entrypoint"  // Entry point hijacking
	MethodTLSInject   Method = "tlsinject"   // TLS injection
	MethodEAT         Method = "eat"         // Export address table patching (DLL only)
)

// Options holds injection options
type Options struct {
	Method      Method `json:"method"`
	PreserveSig bool   `json:"preserveSig"` // Whether to preserve digital signature
	FuncName    string `json:"funcName"`    // Function name for EAT mode
	Backup      bool   `json:"backup"`      // Whether to create backup
}

// Result holds injection result
type Result struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	OutputPath    string `json:"outputPath"`
	OriginalSize  int64  `json:"originalSize"`
	ModifiedSize  int64  `json:"modifiedSize"`
}

// Injector is the main injector interface
type Injector struct {
	options Options
}

// NewInjector creates a new injector instance
func NewInjector(options Options) *Injector {
	return &Injector{
		options: options,
	}
}

// Inject performs code injection into a PE file
func (i *Injector) Inject(pePath, shellcodePath string) (*Result, error) {
	// Read shellcode
	shellcode, err := os.ReadFile(shellcodePath)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to read shellcode: %v", err),
		}, err
	}

	// Get original file size
	origInfo, err := os.Stat(pePath)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to get file info: %v", err),
		}, err
	}
	origSize := origInfo.Size()

	// Create backup if requested
	if i.options.Backup {
		backupPath := pePath + ".bak"
		if err := copyFile(pePath, backupPath); err != nil {
			return &Result{
				Success: false,
				Message: fmt.Sprintf("Failed to create backup: %v", err),
			}, err
		}
	}

	var result *Result

	switch i.options.Method {
	case MethodFunction:
		result, err = i.injectFunction(pePath, shellcode)
	case MethodEntrypoint:
		result, err = i.injectEntrypoint(pePath, shellcode)
	case MethodTLSInject:
		result, err = i.injectTLS(pePath, shellcode)
	case MethodEAT:
		result, err = i.injectEAT(pePath, shellcode)
	default:
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Unknown injection method: %s", i.options.Method),
		}, fmt.Errorf("unknown injection method: %s", i.options.Method)
	}

	if err == nil && result != nil {
		// Get modified file size
		if modInfo, err := os.Stat(result.OutputPath); err == nil {
			result.ModifiedSize = modInfo.Size()
		}
		result.OriginalSize = origSize
	}

	return result, err
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}
