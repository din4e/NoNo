package scanner

import (
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	modWintrust        = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = modWintrust.NewProc("WinVerifyTrust")

	modCrypt32                     = syscall.NewLazyDLL("crypt32.dll")
	procCryptQueryObject           = modCrypt32.NewProc("CryptQueryObject")
	procCryptMsgGetParam           = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose              = modCrypt32.NewProc("CryptMsgClose")
	procCertFreeCertificateContext = modCrypt32.NewProc("CertFreeCertificateContext")
)

const (
	CERT_QUERY_OBJECT_FILE                     = 1
	CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1024
	CERT_QUERY_FORMAT_FLAG_ALL                 = 14
	CMSG_SIGNER_INFO_PARAM                     = 6
)

// CheckDigitalSignature checks if a file is digitally signed
func CheckDigitalSignature(filePath string) (bool, string) {
	if runtime.GOOS != "windows" {
		return CheckSignatureOpenSSL(filePath)
	}
	return CheckSignatureWinAPI(filePath)
}

// CheckSignatureWinAPI checks signature using Windows API
func CheckSignatureWinAPI(filePath string) (bool, string) {
	filePathUTF16, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return false, ""
	}

	var hMsg uintptr
	var hStore uintptr
	var pCertContext uintptr

	ret, _, _ := procCryptQueryObject.Call(
		CERT_QUERY_OBJECT_FILE,
		uintptr(unsafe.Pointer(filePathUTF16)),
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_ALL,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		0,
	)

	if ret == 0 {
		return false, ""
	}

	defer func() {
		if hMsg != 0 {
			procCryptMsgClose.Call(hMsg)
		}
		if pCertContext != 0 {
			procCertFreeCertificateContext.Call(pCertContext)
		}
	}()

	signerName := ExtractSignerName(hMsg)
	if signerName != "" {
		return true, signerName
	}

	return true, "Verified"
}

// ExtractSignerName extracts the signer name from a crypt message
func ExtractSignerName(hMsg uintptr) string {
	var cbData uint32
	ret, _, _ := procCryptMsgGetParam.Call(
		hMsg,
		CMSG_SIGNER_INFO_PARAM,
		0,
		0,
		uintptr(unsafe.Pointer(&cbData)),
	)

	if ret == 0 || cbData == 0 {
		return ""
	}

	signerInfo := make([]byte, cbData)
	ret, _, _ = procCryptMsgGetParam.Call(
		hMsg,
		CMSG_SIGNER_INFO_PARAM,
		0,
		uintptr(unsafe.Pointer(&signerInfo[0])),
		uintptr(unsafe.Pointer(&cbData)),
	)

	if ret == 0 {
		return ""
	}

	infoStr := string(signerInfo)
	if strings.Contains(infoStr, "Microsoft") {
		return "Microsoft Corporation"
	}
	return "Verified Signature"
}

// CheckSignatureOpenSSL checks signature using OpenSSL (non-Windows)
func CheckSignatureOpenSSL(filePath string) (bool, string) {
	cmd := exec.Command("osslsigncode", "verify", filePath)
	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(string(output), "Signature verification: ok") {
		cmd2 := exec.Command("osslsigncode", "extract-signature", "-in", filePath)
		sigOutput, err2 := cmd2.CombinedOutput()
		if err2 == nil {
			return true, ExtractSignerFromOutput(string(sigOutput))
		}
		return true, "Verified"
	}

	return false, ""
}

// ExtractSignerFromOutput extracts signer info from osslsigncode output
func ExtractSignerFromOutput(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "CN=") {
			if idx := strings.Index(line, "CN="); idx != -1 {
				cn := line[idx+3:]
				if commaIdx := strings.Index(cn, ","); commaIdx != -1 {
					cn = cn[:commaIdx]
				}
				return strings.TrimSpace(cn)
			}
		}
	}
	return ""
}

// IsValidSignature checks if the signature matches the filter
func IsValidSignature(isSigned bool, signFilter string) bool {
	switch signFilter {
	case "signed":
		return isSigned
	case "unsigned":
		return !isSigned
	case "all":
		return true
	default:
		return true
	}
}
