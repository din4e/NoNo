package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/nono/internal/scanner"
)

func main() {
	var config scanner.ScanConfig

	flag.StringVar(&config.Directory, "dir", "C:\\Program Files\\", "Directory to scan")
	flag.Int64Var(&config.MinSize, "min", 0, "Minimum file size (bytes)")
	flag.Int64Var(&config.MaxSize, "max", 61440, "Maximum file size (bytes, 0 for unlimited)")
	flag.StringVar(&config.Architecture, "arch", "x64", "Architecture: x86, x64, both")
	flag.IntVar(&config.Workers, "workers", runtime.NumCPU(), "Number of worker threads")
	flag.StringVar(&config.SignFilter, "sign", "signed", "Signature filter: signed, unsigned, all")
	flag.BoolVar(&config.ShowImports, "imports", true, "Show import table information")
	flag.BoolVar(&config.DetailedDump, "detail", false, "Show detailed import function list")
	extensionsFlag := flag.String("ext", "exe", "File extensions (comma-separated)")
	flag.Parse()

	// Validate signature filter
	config.SignFilter = strings.ToLower(config.SignFilter)
	if config.SignFilter != "signed" && config.SignFilter != "unsigned" && config.SignFilter != "all" {
		fmt.Printf("Error: Invalid signature filter '%s', should be: signed, unsigned, all\n", config.SignFilter)
		os.Exit(1)
	}

	// Process extensions
	config.Extensions = strings.Split(*extensionsFlag, ",")
	for i := range config.Extensions {
		config.Extensions[i] = strings.TrimSpace(strings.ToLower(config.Extensions[i]))
		if !strings.HasPrefix(config.Extensions[i], ".") {
			config.Extensions[i] = "." + config.Extensions[i]
		}
	}

	fmt.Printf("[*] Scan Configuration:\n")
	fmt.Printf("    Directory: %s\n", config.Directory)
	fmt.Printf("    Size: %d - %d bytes\n", config.MinSize, config.MaxSize)
	fmt.Printf("    Architecture: %s\n", config.Architecture)
	fmt.Printf("    Signature Filter: %s\n", config.SignFilter)
	fmt.Printf("    Extensions: %v\n", config.Extensions)
	fmt.Printf("    Workers: %d\n", config.Workers)
	fmt.Println()

	// Create and run scanner
	s := scanner.NewScanner(config)

	s.OnProgress(func(p scanner.ScanProgress) {
		fmt.Printf("\r[*] Progress: %d/%d files scanned, %d found", p.ScannedFiles, p.TotalFiles, p.FoundFiles)
	})

	if err := s.Run(); err != nil {
		fmt.Printf("\nError: %v\n", err)
		os.Exit(1)
	}

	results := s.GetResults()
	fmt.Printf("\n\n[*] Scan Complete. Found %d files.\n\n", len(results))

	// Display results
	if config.DetailedDump {
		displayDetailedResults(results)
	} else {
		displaySummaryResults(results, config)
	}
}

func displayDetailedResults(files []scanner.FileInfo) {
	for _, file := range files {
		fmt.Printf("\n=== %s ===\n", file.Path)
		fmt.Printf("Size: %s | Architecture: %s | Signature: %v",
			formatSize(file.Size), file.Architecture, file.IsSigned)
		if file.IsSigned && file.SignerInfo != "" {
			fmt.Printf(" (%s)", file.SignerInfo)
		}
		fmt.Println()

		if len(file.ImportedDLLs) == 0 {
			fmt.Println("No import table information")
			continue
		}

		fmt.Printf("Imports %d DLLs with %d functions:\n", len(file.ImportedDLLs), file.ImportCount)

		for _, imp := range file.ImportedDLLs {
			fmt.Printf("\n  [%s] (%d functions)\n", imp.DLLName, len(imp.Functions))
			for i, fn := range imp.Functions {
				if i < 20 {
					fmt.Printf("    - %s\n", fn)
				} else if i == 20 {
					fmt.Printf("    ... and %d more functions\n", len(imp.Functions)-20)
					break
				}
			}
		}
	}
}

func displaySummaryResults(files []scanner.FileInfo, config scanner.ScanConfig) {
	signedCount := 0
	unsignedCount := 0

	for _, file := range files {
		if file.IsSigned {
			signedCount++
		} else {
			unsignedCount++
		}
	}

	// Print header
	fmt.Printf("%-50s %-10s %-8s %-10s %s\n", "File Path", "Size", "Arch", "Signature", "Signer")
	fmt.Println(strings.Repeat("-", 100))

	// Print results
	for _, file := range files {
		signStatus := "Unsigned"
		if file.IsSigned {
			signStatus = "Signed"
		}

		signerDisplay := file.SignerInfo
		if len(signerDisplay) > 20 {
			signerDisplay = signerDisplay[:17] + "..."
		}

		fmt.Printf("%-50s %-10s %-8s %-10s %s\n",
			truncatePath(file.Path, 50),
			formatSize(file.Size),
			file.Architecture,
			signStatus,
			signerDisplay)
	}

	// Print statistics
	fmt.Printf("\nStatistics:\n")
	fmt.Printf("  Total Files: %d\n", len(files))
	fmt.Printf("  Signed: %d | Unsigned: %d\n", signedCount, unsignedCount)
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

	// Try to keep the filename
	parts := strings.Split(path, string(os.PathSeparator))
	fileName := parts[len(parts)-1]

	if len(fileName) < maxLen-10 {
		prefix := path[:maxLen-len(fileName)-4]
		return prefix + "..." + fileName
	}

	return "..." + path[len(path)-maxLen+3:]
}
