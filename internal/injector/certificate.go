package injector

import (
	"encoding/binary"
	"fmt"
	"os"
)

// Certificate directory info
const (
	CERT_DIRECTORY_INDEX = 4 // Security directory index in data directories
)

// ClearSignature removes the digital signature from a PE file
func ClearSignature(pePath string) error {
	// Read file
	data, err := os.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Check DOS header
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return fmt.Errorf("invalid PE file")
	}

	// Get PE offset
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	if peOffset >= uint32(len(data)) {
		return fmt.Errorf("invalid PE header offset")
	}

	// Check PE signature
	if data[peOffset] != 'P' || data[peOffset+1] != 'E' {
		return fmt.Errorf("invalid PE signature")
	}

	// Get optional header info
	optHeaderOffset := peOffset + 4
	magic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])

	var certDirOffset, certDirSizeOffset uint32
	var numRvaAndSizes uint32

	if magic == 0x10b { // PE32
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optHeaderOffset+92 : optHeaderOffset+96])
		if numRvaAndSizes <= CERT_DIRECTORY_INDEX {
			return nil // No certificate directory
		}
		certDirOffset = optHeaderOffset + 96 + CERT_DIRECTORY_INDEX*8
		certDirSizeOffset = certDirOffset + 4
	} else if magic == 0x20b { // PE32+
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optHeaderOffset+108 : optHeaderOffset+112])
		if numRvaAndSizes <= CERT_DIRECTORY_INDEX {
			return nil // No certificate directory
		}
		certDirOffset = optHeaderOffset + 112 + CERT_DIRECTORY_INDEX*8
		certDirSizeOffset = certDirOffset + 4
	} else {
		return fmt.Errorf("unknown PE format")
	}

	// Get certificate directory info
	certRVA := binary.LittleEndian.Uint32(data[certDirOffset : certDirOffset+4])
	certSize := binary.LittleEndian.Uint32(data[certDirSizeOffset : certDirSizeOffset+4])

	if certRVA == 0 || certSize == 0 {
		return nil // No signature to clear
	}

	// Clear the certificate directory entry
	binary.LittleEndian.PutUint32(data[certDirOffset:], 0)
	binary.LittleEndian.PutUint32(data[certDirSizeOffset:], 0)

	// Truncate the file to remove the certificate data
	// Certificate data is typically at the end of the file
	if certRVA < uint32(len(data)) {
		data = data[:certRVA]
	}

	// Write modified file
	if err := os.WriteFile(pePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// CopySignature copies a digital signature from one PE file to another
// Note: This will create an invalid signature but can help bypass basic checks
func CopySignature(srcPE, dstPE string) error {
	// Read source file
	srcData, err := os.ReadFile(srcPE)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Read destination file
	dstData, err := os.ReadFile(dstPE)
	if err != nil {
		return fmt.Errorf("failed to read destination file: %w", err)
	}

	// Extract certificate from source
	certData, _, certSize, err := extractCertificate(srcData)
	if err != nil {
		return fmt.Errorf("failed to extract certificate: %w", err)
	}

	if certSize == 0 {
		return fmt.Errorf("source file has no signature")
	}

	// Append certificate to destination
	newDstData := make([]byte, len(dstData)+len(certData))
	copy(newDstData, dstData)
	copy(newDstData[len(dstData):], certData)

	// Update certificate directory in destination
	newCertRVA := uint32(len(dstData))

	peOffset := binary.LittleEndian.Uint32(newDstData[60:64])
	optHeaderOffset := peOffset + 4
	magic := binary.LittleEndian.Uint16(newDstData[optHeaderOffset : optHeaderOffset+2])

	var certDirOffset uint32
	if magic == 0x10b { // PE32
		certDirOffset = optHeaderOffset + 96 + CERT_DIRECTORY_INDEX*8
	} else if magic == 0x20b { // PE32+
		certDirOffset = optHeaderOffset + 112 + CERT_DIRECTORY_INDEX*8
	} else {
		return fmt.Errorf("unknown PE format")
	}

	// Write new certificate directory
	binary.LittleEndian.PutUint32(newDstData[certDirOffset:], newCertRVA)
	binary.LittleEndian.PutUint32(newDstData[certDirOffset+4:], uint32(len(certData)))

	// Write modified file
	if err := os.WriteFile(dstPE, newDstData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// extractCertificate extracts the certificate data from a PE file
func extractCertificate(data []byte) ([]byte, uint32, uint32, error) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return nil, 0, 0, fmt.Errorf("invalid PE file")
	}

	peOffset := binary.LittleEndian.Uint32(data[60:64])
	if peOffset >= uint32(len(data)) {
		return nil, 0, 0, fmt.Errorf("invalid PE header offset")
	}

	optHeaderOffset := peOffset + 4
	magic := binary.LittleEndian.Uint16(data[optHeaderOffset : optHeaderOffset+2])

	var certDirOffset uint32
	var numRvaAndSizes uint32

	if magic == 0x10b { // PE32
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optHeaderOffset+92 : optHeaderOffset+96])
		if numRvaAndSizes <= CERT_DIRECTORY_INDEX {
			return nil, 0, 0, nil
		}
		certDirOffset = optHeaderOffset + 96 + CERT_DIRECTORY_INDEX*8
	} else if magic == 0x20b { // PE32+
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optHeaderOffset+108 : optHeaderOffset+112])
		if numRvaAndSizes <= CERT_DIRECTORY_INDEX {
			return nil, 0, 0, nil
		}
		certDirOffset = optHeaderOffset + 112 + CERT_DIRECTORY_INDEX*8
	} else {
		return nil, 0, 0, fmt.Errorf("unknown PE format")
	}

	certRVA := binary.LittleEndian.Uint32(data[certDirOffset : certDirOffset+4])
	certSize := binary.LittleEndian.Uint32(data[certDirOffset+4 : certDirOffset+8])

	if certRVA == 0 || certSize == 0 {
		return nil, 0, 0, nil
	}

	if certRVA+certSize > uint32(len(data)) {
		return nil, 0, 0, fmt.Errorf("certificate data out of bounds")
	}

	certData := make([]byte, certSize)
	copy(certData, data[certRVA:certRVA+certSize])

	return certData, certRVA, certSize, nil
}

// GetCertificateInfo returns information about the certificate in a PE file
func GetCertificateInfo(pePath string) (hasSig bool, rva uint32, size uint32, err error) {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return false, 0, 0, err
	}

	_, rva, size, err = extractCertificate(data)
	if err != nil {
		return false, 0, 0, err
	}

	return size > 0, rva, size, nil
}
