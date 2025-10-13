package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type FileInfo struct {
	Path         string
	Size         int64
	Architecture string
	IsSigned     bool
	SignerInfo   string
	ImportedDLLs []ImportInfo // 修改：详细的导入信息
	ImportCount  int          // 导入函数总数
}

type ImportInfo struct {
	DLLName   string
	Functions []string
}

type ScanConfig struct {
	Directory    string
	MinSize      int64
	MaxSize      int64
	Architecture string
	Extensions   []string
	Workers      int
	SignFilter   string
	ShowImports  bool
	DetailedDump bool // 新增：是否显示详细的导入函数列表
}

type FileTask struct {
	Path string
	Info fs.FileInfo
}

// PE相关结构体
type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

var (
	modWintrust        = syscall.NewLazyDLL("wintrust.dll")
	procWinVerifyTrust = modWintrust.NewProc("WinVerifyTrust")

	modCrypt32                     = syscall.NewLazyDLL("crypt32.dll")
	procCryptQueryObject           = modCrypt32.NewProc("CryptQueryObject")
	procCertGetNameString          = modCrypt32.NewProc("CertGetNameStringW")
	procCryptMsgGetParam           = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose              = modCrypt32.NewProc("CryptMsgClose")
	procCertFreeCertificateContext = modCrypt32.NewProc("CertFreeCertificateContext")
)

const (
	CERT_QUERY_OBJECT_FILE                     = 1
	CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1024
	CERT_QUERY_FORMAT_FLAG_ALL                 = 14
	CMSG_SIGNER_INFO_PARAM                     = 6
	CERT_NAME_SIMPLE_DISPLAY_TYPE              = 4
)

func main() {
	var config ScanConfig

	flag.StringVar(&config.Directory, "dir", "C:\\Program Files\\", "要扫描的目录路径")
	flag.Int64Var(&config.MinSize, "min", 0, "最小文件大小 (字节)")
	flag.Int64Var(&config.MaxSize, "max", 61440, "最大文件大小 (字节，0表示无限制)")
	flag.StringVar(&config.Architecture, "arch", "x64", "架构类型: x86, x64, both")
	flag.IntVar(&config.Workers, "workers", runtime.NumCPU(), "工作线程数")
	flag.StringVar(&config.SignFilter, "signed", "signed", "签名过滤: signed(仅已签名), unsigned(仅未签名), all(全部)")
	flag.BoolVar(&config.ShowImports, "imports", true, "显示导入表DLL信息")
	flag.BoolVar(&config.DetailedDump, "detail", false, "显示详细的导入函数列表")
	extensionsFlag := flag.String("ext", "exe", "文件扩展名，用逗号分隔")
	flag.Parse()

	// 验证签名过滤参数
	config.SignFilter = strings.ToLower(config.SignFilter)
	if config.SignFilter != "signed" && config.SignFilter != "unsigned" && config.SignFilter != "all" {
		fmt.Printf("错误: 无效的签名过滤参数 '%s'，应为: signed, unsigned, all\n", config.SignFilter)
		os.Exit(1)
	}

	// 处理扩展名
	config.Extensions = strings.Split(*extensionsFlag, ",")
	for i := range config.Extensions {
		config.Extensions[i] = strings.TrimSpace(strings.ToLower(config.Extensions[i]))
		if !strings.HasPrefix(config.Extensions[i], ".") {
			config.Extensions[i] = "." + config.Extensions[i]
		}
	}

	// 获取绝对路径
	absDir, err := filepath.Abs(config.Directory)
	if err == nil {
		config.Directory = absDir
	}

	fmt.Printf("[*] 扫描配置:\n目录:%s | 大小:%d-%dB | 架构:%s | 签名=%s | 扩展名:%v | 线程:%d\n",
		config.Directory, config.MinSize, config.MaxSize, config.Architecture, config.SignFilter, config.Extensions, config.Workers)
	if config.ShowImports {
		fmt.Printf("[*]导入表分析: 启用")
		if config.DetailedDump {
			fmt.Printf(" (详细模式)")
		}
		fmt.Println()
	}
	fmt.Println()

	// 程序的主要功能代码
	files := scanDirectory(config)

	if config.DetailedDump {
		// 详细模式：显示每个文件的完整导入信息
		displayDetailedImports(files, config)
	} else {
		// 简要模式：显示概览信息
		displaySummaryImports(files, config)
	}
}

func displayDetailedImports(files []FileInfo, config ScanConfig) {
	for _, file := range files {
		fmt.Printf("\n=== %s ===\n", file.Path)
		fmt.Printf("大小: %s | 架构: %s | 签名: %s",
			formatSize(file.Size), file.Architecture,
			map[bool]string{true: "已签名", false: "未签名"}[file.IsSigned])
		if file.IsSigned && file.SignerInfo != "" {
			fmt.Printf(" (%s)", file.SignerInfo)
		}
		fmt.Println()

		if len(file.ImportedDLLs) == 0 {
			fmt.Println("无导入表信息")
			continue
		}

		fmt.Printf("导入 %d 个DLL，共 %d 个函数:\n", len(file.ImportedDLLs), file.ImportCount)

		for _, imp := range file.ImportedDLLs {
			fmt.Printf("\n  [%s] (%d 个函数)\n", imp.DLLName, len(imp.Functions))
			for i, fn := range imp.Functions {
				if i < 20 { // 限制显示前20个函数
					fmt.Printf("    - %s\n", fn)
				} else if i == 20 {
					fmt.Printf("    ... 还有 %d 个函数\n", len(imp.Functions)-20)
					break
				}
			}
		}
	}
}

func displaySummaryImports(files []FileInfo, config ScanConfig) {
	// 统计信息
	signedCount := 0
	unsignedCount := 0
	totalImports := 0
	dllFrequency := make(map[string]int)

	for _, file := range files {
		if file.IsSigned {
			signedCount++
		} else {
			unsignedCount++
		}
		totalImports += file.ImportCount

		// 统计DLL使用频率
		for _, imp := range file.ImportedDLLs {
			dllFrequency[strings.ToLower(imp.DLLName)]++
		}
	}

	// 输出表头
	if config.ShowImports {
		fmt.Printf("%-50s %-8s %-6s %-8s %-6s %-30s %s\n",
			"文件路径", "大小", "架构", "签名", "导入数", "主要DLL", "签名者")
		fmt.Println(strings.Repeat("-", 140))
	} else {
		fmt.Printf("%-60s %-10s %-8s %-10s %s\n",
			"文件路径", "大小", "架构", "签名状态", "签名者")
		fmt.Println(strings.Repeat("-", 120))
	}

	// 输出结果
	for _, file := range files {
		sizeDisplay := formatSize(file.Size)
		signStatus := map[bool]string{true: "已签名", false: "未签名"}[file.IsSigned]

		signerDisplay := file.SignerInfo
		if len(signerDisplay) > 25 {
			signerDisplay = signerDisplay[:22] + "..."
		}

		if config.ShowImports {
			mainDLLs := getTopDLLNames(file.ImportedDLLs, 2)
			fmt.Printf("%-50s %-8s %-6s %-8s %-6d %-30s %s\n",
				truncatePath(file.Path, 50),
				sizeDisplay,
				file.Architecture,
				signStatus,
				file.ImportCount,
				strings.Join(mainDLLs, ", "),
				signerDisplay)
		} else {
			fmt.Printf("%-60s %-10s %-8s %-10s %s\n",
				truncatePath(file.Path, 60),
				sizeDisplay,
				file.Architecture,
				signStatus,
				signerDisplay)
		}
	}

	// 输出统计信息
	fmt.Printf("\n统计信息:\n")
	fmt.Printf("  总计文件: %d 个\n", len(files))
	fmt.Printf("  已签名: %d 个 | 未签名: %d 个\n", signedCount, unsignedCount)

	//if config.ShowImports && len(files) > 0 {
	//	fmt.Printf("  导入函数总数: %d 个\n", totalImports)
	//	fmt.Printf("  平均每文件导入: %.1f 个\n", float64(totalImports)/float64(len(files)))
	//
	//	// 显示最常用的DLL
	//	fmt.Printf("\n最常用的DLL (前10个):\n")
	//	sortedDLLs := sortMapByValue(dllFrequency)
	//	count := 0
	//	for _, item := range sortedDLLs {
	//		if count >= 10 {
	//			break
	//		}
	//		percentage := float64(item.Value) / float64(len(files)) * 100
	//		fmt.Printf("  %-25s: %3d 个文件 (%.1f%%)\n", item.Key, item.Value, percentage)
	//		count++
	//	}
	//}
}

// 修改后的导入表解析函数
func getImportTable(filename string) ([]ImportInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 先用标准库检查是否为有效PE文件
	peFile, err := pe.Open(filename)
	if err != nil {
		return nil, err
	}
	defer peFile.Close()

	// 读取文件内容
	fileData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return parseImportTable(fileData)
}

func parseImportTable(data []byte) ([]ImportInfo, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("文件太小，不是有效的PE文件")
	}

	// 检查DOS头
	if !bytes.Equal(data[0:2], []byte("MZ")) {
		return nil, fmt.Errorf("无效的DOS头")
	}

	// 获取PE头偏移
	peOffset := binary.LittleEndian.Uint32(data[60:64])
	if peOffset >= uint32(len(data)) {
		return nil, fmt.Errorf("无效的PE头偏移")
	}

	// 检查PE签名
	if !bytes.Equal(data[peOffset:peOffset+4], []byte("PE\x00\x00")) {
		return nil, fmt.Errorf("无效的PE签名")
	}

	// 解析COFF头
	coffHeaderOffset := peOffset + 4
	if coffHeaderOffset+20 > uint32(len(data)) {
		return nil, fmt.Errorf("COFF头超出文件范围")
	}

	optionalHeaderSize := binary.LittleEndian.Uint16(data[coffHeaderOffset+16 : coffHeaderOffset+18])

	// 计算可选头偏移
	optionalHeaderOffset := coffHeaderOffset + 20
	if optionalHeaderOffset+uint32(optionalHeaderSize) > uint32(len(data)) {
		return nil, fmt.Errorf("可选头超出文件范围")
	}

	// 判断是32位还是64位
	magic := binary.LittleEndian.Uint16(data[optionalHeaderOffset : optionalHeaderOffset+2])

	var importTableRVA, importTableSize uint32
	var numRvaAndSizes uint32

	if magic == 0x10b { // PE32
		if optionalHeaderSize < 96 {
			return nil, fmt.Errorf("PE32可选头太小")
		}
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optionalHeaderOffset+92 : optionalHeaderOffset+96])
		if numRvaAndSizes >= 2 {
			importTableRVA = binary.LittleEndian.Uint32(data[optionalHeaderOffset+104 : optionalHeaderOffset+108])
			importTableSize = binary.LittleEndian.Uint32(data[optionalHeaderOffset+108 : optionalHeaderOffset+112])
		}
	} else if magic == 0x20b { // PE32+
		if optionalHeaderSize < 112 {
			return nil, fmt.Errorf("PE32+可选头太小")
		}
		numRvaAndSizes = binary.LittleEndian.Uint32(data[optionalHeaderOffset+108 : optionalHeaderOffset+112])
		if numRvaAndSizes >= 2 {
			importTableRVA = binary.LittleEndian.Uint32(data[optionalHeaderOffset+120 : optionalHeaderOffset+124])
			importTableSize = binary.LittleEndian.Uint32(data[optionalHeaderOffset+124 : optionalHeaderOffset+128])
		}
	} else {
		return nil, fmt.Errorf("不支持的PE格式")
	}

	if importTableRVA == 0 || importTableSize == 0 {
		return []ImportInfo{}, nil // 没有导入表
	}

	// 解析节表以找到导入表的文件偏移
	sectionHeadersOffset := optionalHeaderOffset + uint32(optionalHeaderSize)
	numberOfSections := binary.LittleEndian.Uint16(data[coffHeaderOffset+2 : coffHeaderOffset+4])

	importTableOffset, err := rvaToFileOffset(data, importTableRVA, sectionHeadersOffset, numberOfSections)
	if err != nil {
		return nil, err
	}

	// 解析导入描述符
	var imports []ImportInfo
	offset := importTableOffset

	for {
		if offset+20 > uint32(len(data)) {
			break
		}

		// 读取导入描述符
		var desc ImageImportDescriptor
		desc.OriginalFirstThunk = binary.LittleEndian.Uint32(data[offset : offset+4])
		desc.TimeDateStamp = binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		desc.ForwarderChain = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		desc.Name = binary.LittleEndian.Uint32(data[offset+12 : offset+16])
		desc.FirstThunk = binary.LittleEndian.Uint32(data[offset+16 : offset+20])

		// 检查是否为结束标记
		if desc.Name == 0 {
			break
		}

		// 获取DLL名称
		nameOffset, err := rvaToFileOffset(data, desc.Name, sectionHeadersOffset, numberOfSections)
		if err != nil {
			offset += 20
			continue
		}

		dllName := readNullTerminatedString(data, nameOffset)
		if dllName == "" {
			offset += 20
			continue
		}

		// 获取导入函数列表
		functions := parseImportFunctions(data, desc, sectionHeadersOffset, numberOfSections, magic == 0x20b)

		imports = append(imports, ImportInfo{
			DLLName:   dllName,
			Functions: functions,
		})

		offset += 20
	}

	return imports, nil
}

func parseImportFunctions(data []byte, desc ImageImportDescriptor, sectionHeadersOffset uint32, numberOfSections uint16, is64bit bool) []string {
	var functions []string

	// 使用OriginalFirstThunk，如果为0则使用FirstThunk
	thunkRVA := desc.OriginalFirstThunk
	if thunkRVA == 0 {
		thunkRVA = desc.FirstThunk
	}

	if thunkRVA == 0 {
		return functions
	}

	thunkOffset, err := rvaToFileOffset(data, thunkRVA, sectionHeadersOffset, numberOfSections)
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

		// 检查是否为序号导入
		ordinalFlag := uint64(0x80000000)
		if is64bit {
			ordinalFlag = 0x8000000000000000
		}

		if thunkValue&ordinalFlag != 0 {
			// 序号导入
			ordinal := thunkValue & 0xFFFF
			functions = append(functions, fmt.Sprintf("Ordinal_%d", ordinal))
		} else {
			// 名称导入
			nameRVA := uint32(thunkValue & 0x7FFFFFFF)
			nameOffset, err := rvaToFileOffset(data, nameRVA, sectionHeadersOffset, numberOfSections)
			if err != nil {
				functions = append(functions, "Unknown")
			} else {
				// 跳过提示值（2字节）
				if nameOffset+2 < uint32(len(data)) {
					funcName := readNullTerminatedString(data, nameOffset+2)
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

func rvaToFileOffset(data []byte, rva uint32, sectionHeadersOffset uint32, numberOfSections uint16) (uint32, error) {
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

	return 0, fmt.Errorf("无法找到RVA对应的文件偏移")
}

func readNullTerminatedString(data []byte, offset uint32) string {
	if offset >= uint32(len(data)) {
		return ""
	}

	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

func getTopDLLNames(imports []ImportInfo, n int) []string {
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

func countTotalImports(imports []ImportInfo) int {
	total := 0
	for _, imp := range imports {
		total += len(imp.Functions)
	}
	return total
}

type KeyValue struct {
	Key   string
	Value int
}

func sortMapByValue(m map[string]int) []KeyValue {
	var pairs []KeyValue
	for k, v := range m {
		pairs = append(pairs, KeyValue{k, v})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Value > pairs[j].Value
	})

	return pairs
}

func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	kb := float64(bytes) / 1024.0
	if kb < 1024 {
		return fmt.Sprintf("%.0fK", kb)
	}
	mb := kb / 1024.0
	if mb < 1024 {
		return fmt.Sprintf("%.1fM", mb)
	}
	gb := mb / 1024.0
	return fmt.Sprintf("%.1fG", gb)
}

func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}

	fileName := filepath.Base(path)
	if len(fileName) < maxLen-10 {
		prefix := path[:maxLen-len(fileName)-4]
		return prefix + "..." + fileName
	}

	return "..." + path[len(path)-maxLen+3:]
}

func scanDirectory(config ScanConfig) []FileInfo {
	taskChan := make(chan FileTask, 1000)
	resultChan := make(chan FileInfo, 1000)
	done := make(chan bool)

	var wg sync.WaitGroup
	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		go worker(taskChan, resultChan, config, &wg)
	}

	var results []FileInfo
	var resultWg sync.WaitGroup
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for {
			select {
			case result := <-resultChan:
				results = append(results, result)
			case <-done:
				for len(resultChan) > 0 {
					results = append(results, <-resultChan)
				}
				return
			}
		}
	}()

	filepath.WalkDir(config.Directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			return nil
		}

		if !hasValidExtension(path, config.Extensions) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if !isValidSize(info.Size(), config.MinSize, config.MaxSize) {
			return nil
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			absPath = path
		}

		select {
		case taskChan <- FileTask{Path: absPath, Info: info}:
		default:
			if result := processFile(absPath, info, config); result != nil {
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

	return results
}

func worker(taskChan <-chan FileTask, resultChan chan<- FileInfo, config ScanConfig, wg *sync.WaitGroup) {
	defer wg.Done()

	for task := range taskChan {
		if result := processFile(task.Path, task.Info, config); result != nil {
			select {
			case resultChan <- *result:
			default:
			}
		}
	}
}

func processFile(path string, info fs.FileInfo, config ScanConfig) *FileInfo {
	arch, err := getFileArchitecture(path)
	if err != nil {
		return nil
	}

	if !isValidArchitecture(arch, config.Architecture) {
		return nil
	}

	isSigned, signerInfo := checkDigitalSignature(path)

	if !isValidSignature(isSigned, config.SignFilter) {
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

	// 获取导入表信息
	if config.ShowImports {
		imports, err := getImportTable(path)
		if err == nil {
			fileInfo.ImportedDLLs = imports
			fileInfo.ImportCount = countTotalImports(imports)
		}
	}

	return fileInfo
}

func isValidSignature(isSigned bool, signFilter string) bool {
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

func checkDigitalSignature(filePath string) (bool, string) {
	if runtime.GOOS != "windows" {
		return checkSignatureOpenSSL(filePath)
	}
	return checkSignatureWinAPI(filePath)
}

func checkSignatureWinAPI(filePath string) (bool, string) {
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

	signerName := extractSignerName(hMsg)
	if signerName != "" {
		return true, signerName
	}

	return true, "已验证"
}

func extractSignerName(hMsg uintptr) string {
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
	return "已验证签名"
}

func checkSignatureOpenSSL(filePath string) (bool, string) {
	cmd := exec.Command("osslsigncode", "verify", filePath)
	output, err := cmd.CombinedOutput()

	if err == nil && strings.Contains(string(output), "Signature verification: ok") {
		cmd2 := exec.Command("osslsigncode", "extract-signature", "-in", filePath)
		sigOutput, err2 := cmd2.CombinedOutput()
		if err2 == nil {
			return true, extractSignerFromOutput(string(sigOutput))
		}
		return true, "已验证"
	}

	return false, ""
}

func extractSignerFromOutput(output string) string {
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

func hasValidExtension(filename string, validExtensions []string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, validExt := range validExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

func isValidSize(size, minSize, maxSize int64) bool {
	if size < minSize {
		return false
	}
	if maxSize > 0 && size > maxSize {
		return false
	}
	return true
}

func getFileArchitecture(filename string) (string, error) {
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

func isValidArchitecture(fileArch, targetArch string) bool {
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
