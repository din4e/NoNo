// Package config provides configuration management for NoNo
package config

// AppConfig holds application configuration
type AppConfig struct {
	// Scanner defaults
	DefaultScanDir    string `json:"defaultScanDir"`
	DefaultMinSize    int64  `json:"defaultMinSize"`
	DefaultMaxSize    int64  `json:"defaultMaxSize"`
	DefaultArch       string `json:"defaultArch"`
	DefaultSignFilter string `json:"defaultSignFilter"`
	DefaultWorkers    int    `json:"defaultWorkers"`
}

// DefaultConfig returns the default application configuration
func DefaultConfig() *AppConfig {
	return &AppConfig{
		DefaultScanDir:    "C:\\Program Files\\",
		DefaultMinSize:    0,
		DefaultMaxSize:    61440, // 60KB
		DefaultArch:       "x64",
		DefaultSignFilter: "signed",
		DefaultWorkers:    4,
	}
}

// PEInfo holds detailed PE file information for display
type PEInfo struct {
	Path             string          `json:"path"`
	Size             int64           `json:"size"`
	Architecture     string          `json:"architecture"`
	IsSigned         bool            `json:"isSigned"`
	SignerInfo       string          `json:"signerInfo"`
	ImportedDLLs     []ImportDLLInfo `json:"importedDLLs"`
	ImportCount      int             `json:"importCount"`
	HasTLS           bool            `json:"hasTLS"`
	IsDLL            bool            `json:"isDll"`
	EntryPoint       uint32          `json:"entryPoint"`
	ImageBase        uint64          `json:"imageBase"`
	NumberOfSections uint16          `json:"numberOfSections"`
	HasExport        bool            `json:"hasExport"`
}

// ImportDLLInfo holds DLL import information
type ImportDLLInfo struct {
	DLLName   string   `json:"dllName"`
	Functions []string `json:"functions"`
}

// ScanConfigJSON holds scan configuration for JSON binding
type ScanConfigJSON struct {
	Directory    string   `json:"directory"`
	MinSize      int64    `json:"minSize"`
	MaxSize      int64    `json:"maxSize"`
	Architecture string   `json:"architecture"`
	Extensions   []string `json:"extensions"`
	Workers      int      `json:"workers"`
	SignFilter   string   `json:"signFilter"`
	ShowImports  bool     `json:"showImports"`
}

// InjectConfigJSON holds injection configuration for JSON binding
type InjectConfigJSON struct {
	PEPath       string `json:"pePath"`
	ShellcodePath string `json:"shellcodePath"`
	Method       string `json:"method"`
	PreserveSig  bool   `json:"preserveSig"`
	FuncName     string `json:"funcName"`
	Backup       bool   `json:"backup"`
}
