package scanner

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ImageImportDescriptor represents PE import descriptor
type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

// GetFileArchitecture returns the architecture of a PE file
func GetFileArchitecture(filename string) (string, error) {
	file, err := pe.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	switch file.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86", nil
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x64", nil
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "ARM", nil
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "ARM64", nil
	default:
		return fmt.Sprintf("Unknown(0x%x)", file.Machine), nil
	}
}

// IsValidArchitecture checks if the file architecture matches the target
func IsValidArchitecture(fileArch, targetArch string) bool {
	targetArch = strings.ToLower(targetArch)
	fileArch = strings.ToLower(fileArch)

	switch targetArch {
	case "both":
		return true
	case "x86":
		return fileArch == "x86"
	case "x64":
		return fileArch == "x64"
	default:
		return fileArch == targetArch
	}
}

// HasValidExtension checks if the file has a valid extension
func HasValidExtension(filename string, validExtensions []string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, validExt := range validExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

// IsValidSize checks if the file size is within the valid range
func IsValidSize(size, minSize, maxSize int64) bool {
	if size < minSize {
		return false
	}
	if maxSize > 0 && size > maxSize {
		return false
	}
	return true
}

// GetImportTable returns the import table of a PE file
func GetImportTable(filename string) ([]ImportInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Verify it's a valid PE file
	peFile, err := pe.Open(filename)
	if err != nil {
		return nil, err
	}
	peFile.Close()

	// Read file content
	fileData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return ParseImportTable(fileData)
}

// ParseImportTable parses the import table from PE file data
func ParseImportTable(data []byte) ([]ImportInfo, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small, not a valid PE file")
	}

	// Check DOS header
	if !bytes.Equal(data[0:2], []byte("MZ")) {
		return nil, fmt.Errorf("invalid DOS header")
	}

	// Get PE header offset
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	if peOffset >= uint32(len(data)) {
		return nil, fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if !bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00")) {
		return nil, fmt.Errorf("invalid PE signature")
	}

	// Parse COFF header
	coffHeaderOffset := peOffset + 4
	if coffHeaderOffset+20 > uint32(len(data)) {
		return nil, fmt.Errorf("COFF header out of bounds")
	}

	optionalHeaderSize := binary.LittleEndian.Uint16(data[coffHeaderOffset+16 : coffHeaderOffset+18])

	// Calculate optional header offset
	optionalHeaderOffset := coffHeaderOffset + 20
	if optionalHeaderOffset+uint32(optionalHeaderSize) > uint32(len(data)) {
		return nil, fmt.Errorf("optional header out of bounds")
	}

	// Determine if 32-bit or 64-bit
	magic := binary.LittleEndian.Uint16(data[optionalHeaderOffset : optionalHeaderOffset+2])

	var importTableRVA, importTableSize uint32
	var numRvaAndSizes uint32

	if magic == 0x10b { // PE32
		if optionalHeaderSize < 96 {
			return nil, fmt.Errorf("PE32 optional header too small")
		}
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optionalHeaderOffset+92 : optionalHeaderOffset+96])
		if numRvaAndSizes >= 2 {
			importTableRVA = binary.LittleEndian.Uint32(data[optionalHeaderOffset+104 : optionalHeaderOffset+108])
			importTableSize = binary.LittleEndian.Uint32(data[optionalHeaderOffset+108 : optionalHeaderOffset+112])
		}
	} else if magic == 0x20b { // PE32+
		if optionalHeaderSize < 112 {
			return nil, fmt.Errorf("PE32+ optional header too small")
		}
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optionalHeaderOffset+108 : optionalHeaderOffset+112])
		if numRvaAndSizes >= 2 {
			importTableRVA = binary.LittleEndian.Uint32(data[optionalHeaderOffset+120 : optionalHeaderOffset+124])
			importTableSize = binary.LittleEndian.Uint32(data[optionalHeaderOffset+124 : optionalHeaderOffset+128])
		}
	} else {
		return nil, fmt.Errorf("unsupported PE format")
	}

	if importTableRVA == 0 || importTableSize == 0 {
		return []ImportInfo{}, nil // No import table
	}

	// Parse section headers to find import table file offset
	sectionHeadersOffset := optionalHeaderOffset + uint32(optionalHeaderSize)
	numberOfSections := binary.LittleEndian.Uint16(data[coffHeaderOffset+2 : coffHeaderOffset+4])

	importTableOffset, err := RVAToFileOffset(data, importTableRVA, sectionHeadersOffset, numberOfSections)
	if err != nil {
		return nil, err
	}

	// Parse import descriptors
	var imports []ImportInfo
	offset := importTableOffset

	for {
		if offset+20 > uint32(len(data)) {
			break
		}

		// Read import descriptor
		var desc ImageImportDescriptor
		desc.OriginalFirstThunk = binary.LittleEndian.Uint32(data[offset : offset+4])
		desc.TimeDateStamp = binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		desc.ForwarderChain = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		desc.Name = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		desc.FirstThunk = binary.LittleEndian.Uint32(data[offset+16 : offset+20])

		// Check for end marker
		if desc.Name == 0 {
			break
		}

		// Get DLL name
		nameOffset, err := RVAToFileOffset(data, desc.Name, sectionHeadersOffset, numberOfSections)
		if err != nil {
			offset += 20
			continue
		}

		dllName := ReadNullTerminatedString(data, nameOffset)
		if dllName == "" {
			offset += 20
			continue
		}

		// Get imported function list
		functions := ParseImportFunctions(data, desc, sectionHeadersOffset, numberOfSections, magic == 0x20b)

		imports = append(imports, ImportInfo{
			DLLName:   dllName,
			Functions: functions,
		})

		offset += 20
	}

	return imports, nil
}

// ParseImportFunctions parses imported functions from an import descriptor
func ParseImportFunctions(data []byte, desc ImageImportDescriptor, sectionHeadersOffset uint32, numberOfSections uint16, is64bit bool) []string {
	var functions []string

	// Use OriginalFirstThunk, or FirstThunk if 0
	thunkRVA := desc.OriginalFirstThunk
	if thunkRVA == 0 {
		thunkRVA = desc.FirstThunk
	}

	if thunkRVA == 0 {
		return functions
	}

	thunkOffset, err := RVAToFileOffset(data, thunkRVA, sectionHeadersOffset, numberOfSections)
	if err != nil {
		return functions
	}

	entrySize := 4
	if is64bit {
		entrySize = 8
	}

	offset := thunkOffset
	for {
		if offset+uint32(entrySize) > uint32(len(data)) {
			break
		}

		var thunkValue uint64
		if is64bit {
			thunkValue = binary.LittleEndian.Uint64(data[offset : offset+8])
		} else {
			thunkValue = uint64(binary.LittleEndian.Uint32(data[offset : offset+4]))
		}

		if thunkValue == 0 {
			break
		}

		// Check if ordinal import
		ordinalFlag := uint64(0x80000000)
		if is64bit {
			ordinalFlag = 0x8000000000000000
		}

		if thunkValue&ordinalFlag != 0 {
			// Ordinal import
			ordinal := thunkValue & 0xFFFF
			functions = append(functions, fmt.Sprintf("Ordinal_%d", ordinal))
		} else {
			// Name import
			nameRVA := uint32(thunkValue & 0x7FFFFFFF)
			nameOffset, err := RVAToFileOffset(data, nameRVA, sectionHeadersOffset, numberOfSections)
			if err != nil {
				functions = append(functions, "Unknown")
			} else {
				// Skip hint (2 bytes)
				if nameOffset+2 < uint32(len(data)) {
					funcName := ReadNullTerminatedString(data, nameOffset+2)
					if funcName != "" {
						functions = append(functions, funcName)
					}
				}
			}
		}

		offset += uint32(entrySize)
	}

	return functions
}

// RVAToFileOffset converts RVA to file offset
func RVAToFileOffset(data []byte, rva uint32, sectionHeadersOffset uint32, numberOfSections uint16) (uint32, error) {
	for i := uint16(0); i < numberOfSections; i++ {
		sectionOffset := sectionHeadersOffset + uint32(i)*40
		if sectionOffset+40 > uint32(len(data)) {
			continue
		}

		virtualAddress := binary.LittleEndian.Uint32(data[sectionOffset+12 : sectionOffset+16])
		virtualSize := binary.LittleEndian.Uint32(data[sectionOffset+8 : sectionOffset+12])
		rawDataOffset := binary.LittleEndian.Uint32(data[sectionOffset+20 : sectionOffset+24])

		if rva >= virtualAddress && rva < virtualAddress+virtualSize {
			return rawDataOffset + (rva - virtualAddress), nil
		}
	}

	return 0, fmt.Errorf("cannot find file offset for RVA")
}

// ReadNullTerminatedString reads a null-terminated string from data
func ReadNullTerminatedString(data []byte, offset uint32) string {
	if offset >= uint32(len(data)) {
		return ""
	}

	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

// CountTotalImports counts total imported functions
func CountTotalImports(imports []ImportInfo) int {
	total := 0
	for _, imp := range imports {
		total += len(imp.Functions)
	}
	return total
}

// GetTopDLLNames returns the top N DLL names
func GetTopDLLNames(imports []ImportInfo, n int) []string {
	if len(imports) <= n {
		var names []string
		for _, imp := range imports {
			names = append(names, imp.DLLName)
		}
		return names
	}

	result := make([]string, n)
	for i := 0; i < n; i++ {
		result[i] = imports[i].DLLName
	}
	return result
}
