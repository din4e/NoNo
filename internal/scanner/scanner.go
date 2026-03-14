// Package scanner provides PE file scanning functionality
package scanner

import (
	"io/fs"
	"path/filepath"
	"sync"
)

// FileInfo contains information about a scanned PE file
type FileInfo struct {
	Path         string       `json:"path"`
	Size         int64        `json:"size"`
	Architecture string       `json:"architecture"`
	IsSigned     bool         `json:"isSigned"`
	SignerInfo   string       `json:"signerInfo"`
	ImportedDLLs []ImportInfo `json:"importedDLLs"`
	ImportCount  int          `json:"importCount"`
}

// ImportInfo contains DLL import information
type ImportInfo struct {
	DLLName   string   `json:"dllName"`
	Functions []string `json:"functions"`
}

// ScanConfig holds configuration for scanning
type ScanConfig struct {
	Directory    string   `json:"directory"`
	MinSize      int64    `json:"minSize"`
	MaxSize      int64    `json:"maxSize"`
	Architecture string   `json:"architecture"`
	Extensions   []string `json:"extensions"`
	Workers      int      `json:"workers"`
	SignFilter   string   `json:"signFilter"`
	ShowImports  bool     `json:"showImports"`
	DetailedDump bool     `json:"detailedDump"`
}

// ScanProgress represents the current scan progress
type ScanProgress struct {
	TotalFiles   int `json:"totalFiles"`
	ScannedFiles int `json:"scannedFiles"`
	FoundFiles   int `json:"foundFiles"`
	IsScanning   bool `json:"isScanning"`
}

// FileTask represents a file to be processed
type FileTask struct {
	Path string
	Info fs.FileInfo
}

// Scanner is the main scanner struct
type Scanner struct {
	config      ScanConfig
	progress    ScanProgress
	results     []FileInfo
	stopChan    chan struct{}
	mu          sync.RWMutex
	onProgress  func(ScanProgress)
	onResult    func(FileInfo)
}

// NewScanner creates a new scanner instance
func NewScanner(config ScanConfig) *Scanner {
	return &Scanner{
		config:   config,
		results:  make([]FileInfo, 0),
		stopChan: make(chan struct{}),
	}
}

// OnProgress sets the progress callback
func (s *Scanner) OnProgress(callback func(ScanProgress)) {
	s.mu.Lock()
	s.onProgress = callback
	s.mu.Unlock()
}

// OnResult sets the result callback
func (s *Scanner) OnResult(callback func(FileInfo)) {
	s.mu.Lock()
	s.onResult = callback
	s.mu.Unlock()
}

// GetProgress returns the current scan progress
func (s *Scanner) GetProgress() ScanProgress {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.progress
}

// GetResults returns all scan results
func (s *Scanner) GetResults() []FileInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.results
}

// updateProgress updates the scan progress and calls the callback
func (s *Scanner) updateProgress() {
	s.mu.RLock()
	callback := s.onProgress
	progress := s.progress
	s.mu.RUnlock()

	if callback != nil {
		callback(progress)
	}
}

// addResult adds a result and calls the callback
func (s *Scanner) addResult(info FileInfo) {
	s.mu.Lock()
	s.results = append(s.results, info)
	s.progress.FoundFiles++
	callback := s.onResult
	s.mu.Unlock()

	if callback != nil {
		callback(info)
	}
	s.updateProgress()
}

// Run starts the scanning process
func (s *Scanner) Run() error {
	s.mu.Lock()
	s.progress.IsScanning = true
	s.progress.ScannedFiles = 0
	s.progress.FoundFiles = 0
	s.progress.TotalFiles = 0
	s.results = make([]FileInfo, 0)
	s.mu.Unlock()

	taskChan := make(chan FileTask, 1000)
	resultChan := make(chan FileInfo, 1000)
	done := make(chan bool)

	var wg sync.WaitGroup
	for i := 0; i < s.config.Workers; i++ {
		wg.Add(1)
		go s.worker(taskChan, resultChan, &wg)
	}

	// Result collector
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for {
			select {
			case result := <-resultChan:
				s.addResult(result)
			case <-done:
				for len(resultChan) > 0 {
					s.addResult(<-resultChan)
				}
				return
			}
		}
	}()

	// Walk directory
	filepath.WalkDir(s.config.Directory, func(path string, d fs.DirEntry, err error) error {
		select {
		case <-s.stopChan:
			return fs.SkipAll
		default:
		}

		if err != nil {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		if !HasValidExtension(path, s.config.Extensions) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if !IsValidSize(info.Size(), s.config.MinSize, s.config.MaxSize) {
			return nil
		}

		s.mu.Lock()
		s.progress.TotalFiles++
		s.mu.Unlock()
		s.updateProgress()

		absPath, err := filepath.Abs(path)
		if err != nil {
			absPath = path
		}

		select {
		case taskChan <- FileTask{Path: absPath, Info: info}:
		default:
			if result := s.processFile(absPath, info); result != nil {
				select {
				case resultChan <- *result:
				default:
				}
			}
		}

		return nil
	})

	close(taskChan)
	wg.Wait()
	close(done)
	resultWg.Wait()

	s.mu.Lock()
	s.progress.IsScanning = false
	s.mu.Unlock()
	s.updateProgress()

	return nil
}

// Stop stops the scanning process
func (s *Scanner) Stop() {
	close(s.stopChan)
}

func (s *Scanner) worker(taskChan <-chan FileTask, resultChan chan<- FileInfo, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range taskChan {
		select {
		case <-s.stopChan:
			return
		default:
		}

		if result := s.processFile(task.Path, task.Info); result != nil {
			select {
			case resultChan <- *result:
			default:
			}
		}

		s.mu.Lock()
		s.progress.ScannedFiles++
		s.mu.Unlock()
		s.updateProgress()
	}
}

func (s *Scanner) processFile(path string, info fs.FileInfo) *FileInfo {
	arch, err := GetFileArchitecture(path)
	if err != nil {
		return nil
	}

	if !IsValidArchitecture(arch, s.config.Architecture) {
		return nil
	}

	isSigned, signerInfo := CheckDigitalSignature(path)

	if !IsValidSignature(isSigned, s.config.SignFilter) {
		return nil
	}

	fileInfo := &FileInfo{
		Path:         path,
		Size:         info.Size(),
		Architecture: arch,
		IsSigned:     isSigned,
		SignerInfo:   signerInfo,
		ImportedDLLs: []ImportInfo{},
		ImportCount:  0,
	}

	// Get import table information
	if s.config.ShowImports {
		imports, err := GetImportTable(path)
		if err == nil {
			fileInfo.ImportedDLLs = imports
			fileInfo.ImportCount = CountTotalImports(imports)
		}
	}

	return fileInfo
}
