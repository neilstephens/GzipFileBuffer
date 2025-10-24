package main

import (
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type FieldType int

const (
	FieldSec FieldType = iota
	FieldUsec
	FieldNsec
	FieldLength
	FieldMagic
	FieldIgnore
)

type HeaderField struct {
	Width     int       // 16, 32, 64 bits
	Type      FieldType
	MagicValue uint64   // For magic number fields
}

type BlockHeaderFormat struct {
	Fields       []HeaderField
	TotalBytes   int
	HasLength    bool
	LengthIndex  int
}

type FileBuffer struct {
	filePrefix      string
	maxFileSize     int64
	maxNumFiles     int
	timeFormat      string
	headerBytes     int
	header          []byte
	headerCaptured  bool
	blockFormat     *BlockHeaderFormat
	maxBlockSize    int
	pendingData     []byte // Buffer for data while searching for block boundary
	currentFile     *os.File
	gzipWriter      *gzip.Writer
	currentSize     int64
	fileCounter     int
	activeFiles     []string
}

func main() {
	fileSizeKB := flag.Int64("file_size", 0, "Maximum size per file in kilobytes (required)")
	numFiles := flag.Int("num_files", 0, "Maximum number of files to keep (required)")
	filePrefix := flag.String("file_prefix", "", "Prefix for output files (required)")
	timeFormat := flag.String("time_format", "2006-01-02T15:04:05.000Z", "Time format for filenames (Go time layout)")
	headerBytes := flag.Int("header_bytes", 0, "Number of bytes from start of stream to copy as header for each file (default: 0)")
	blockHeader := flag.String("block_header", "", "Block header format for boundary detection (e.g., <u32:sec><u32:usec><u32:length><u32>)")
	maxBlockSize := flag.Int("max_block_size", 262144, "Maximum block size in bytes when scanning for boundaries (default: 262144 / 256KB)")
	resumeExisting := flag.Bool("resume_existing", false, "Resume with existing files (WARNING: may delete matching files if count exceeds num_files)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GzipFileBuffer - Stream stdin to rotating gzip-compressed files\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Reads binary data from stdin, compresses it with gzip, and writes to a series\n")
		fmt.Fprintf(os.Stderr, "of rotating files. When a file reaches the specified size, it closes and starts\n")
		fmt.Fprintf(os.Stderr, "a new one. Maintains a maximum number of files by deleting the oldest.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nFilename Format:\n")
		fmt.Fprintf(os.Stderr, "  prefix_NNNNNN_TIMESTAMP[.ext].gz\n")
		fmt.Fprintf(os.Stderr, "  where NNNNNN is a zero-padded counter\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  cat data.bin | %s --file_size 10240 --num_files 5 --file_prefix output\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat logs.txt | %s --file_size 51200 --num_files 10 --file_prefix logs.txt\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat stream | %s --file_size 1024 --num_files 3 --file_prefix data --time_format 20060102-150405\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat video.mp4 | %s --file_size 102400 --num_files 5 --file_prefix video.mp4 --header_bytes 1024\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  tcpdump -w - | %s --file_size 102400 --num_files 10 --file_prefix capture.pcap --block_header '<u32:sec><u32:usec><u32:length><u32>'\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Time Format:\n")
		fmt.Fprintf(os.Stderr, "  Uses Go time layout format. Default is ISO 8601: 2006-01-02T15:04:05.000Z\n")
		fmt.Fprintf(os.Stderr, "  Common formats:\n")
		fmt.Fprintf(os.Stderr, "    ISO 8601:     2006-01-02T15:04:05.000Z\n")
		fmt.Fprintf(os.Stderr, "    Simple:       20060102-150405\n\n")
		fmt.Fprintf(os.Stderr, "Header Bytes:\n")
		fmt.Fprintf(os.Stderr, "  Captures the first N bytes of the input stream and prepends them to each\n")
		fmt.Fprintf(os.Stderr, "  subsequent file (after the first). Useful for formats that require headers\n")
		fmt.Fprintf(os.Stderr, "  (e.g., video containers, serialization formats). Set to 0 to disable.\n\n")
		fmt.Fprintf(os.Stderr, "Block Header Format:\n")
		fmt.Fprintf(os.Stderr, "  Specifies block/packet boundary detection to avoid splitting mid-block.\n")
		fmt.Fprintf(os.Stderr, "  Format: <uN:type> where N is bit width (16, 32, 64) and type is:\n")
		fmt.Fprintf(os.Stderr, "    sec     - Unix timestamp seconds (validated within ±48 hours)\n")
		fmt.Fprintf(os.Stderr, "    usec    - Microseconds (0-999999)\n")
		fmt.Fprintf(os.Stderr, "    nsec    - Nanoseconds (0-999999999)\n")
		fmt.Fprintf(os.Stderr, "    length  - Block data length in bytes (0-%d, configurable with --max_block_size)\n", 262144)
		fmt.Fprintf(os.Stderr, "    0xHEX   - Magic number (exact match required)\n")
		fmt.Fprintf(os.Stderr, "    (none)  - Any value (ignored)\n")
		fmt.Fprintf(os.Stderr, "  Example for pcap: <u32:sec><u32:usec><u32:length><u32>\n")
		fmt.Fprintf(os.Stderr, "  All multi-byte values are assumed little-endian.\n\n")
	}

	flag.Parse()

	// Check if help is needed (no args or explicit help)
	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}

	// Validate required arguments
	if *fileSizeKB <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --file_size is required and must be positive")
		flag.Usage()
		os.Exit(1)
	}
	if *numFiles <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --num_files is required and must be positive")
		flag.Usage()
		os.Exit(1)
	}
	if *filePrefix == "" {
		fmt.Fprintln(os.Stderr, "Error: --file_prefix is required")
		flag.Usage()
		os.Exit(1)
	}

	// Validate time format
	if *timeFormat == "" {
		fmt.Fprintln(os.Stderr, "Error: --time_format cannot be empty")
		os.Exit(1)
	}
	if *headerBytes < 0 {
		fmt.Fprintln(os.Stderr, "Error: --header_bytes cannot be negative")
		os.Exit(1)
	}
	if *maxBlockSize <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --max_block_size must be positive")
		os.Exit(1)
	}

	fb := &FileBuffer{
		filePrefix:   *filePrefix,
		maxFileSize:  *fileSizeKB * 1024, // Convert KB to bytes
		maxNumFiles:  *numFiles,
		timeFormat:   *timeFormat,
		headerBytes:  *headerBytes,
		maxBlockSize: *maxBlockSize,
		activeFiles:  make([]string, 0, *numFiles),
		pendingData:  make([]byte, 0),
	}

	// Parse block header format if provided
	if *blockHeader != "" {
		format, err := parseBlockHeaderFormat(*blockHeader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing block header format: %v\n", err)
			os.Exit(1)
		}
		fb.blockFormat = format
		fmt.Fprintf(os.Stderr, "Block header format: %d bytes, %d fields\n", format.TotalBytes, len(format.Fields))
	}

	// Resume from existing files if requested
	if *resumeExisting {
		if err := fb.loadExistingFiles(); err != nil {
			fmt.Fprintf(os.Stderr, "Error loading existing files: %v\n", err)
			os.Exit(1)
		}
	}

	if err := fb.run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseBlockHeaderFormat(format string) (*BlockHeaderFormat, error) {
	result := &BlockHeaderFormat{
		Fields: make([]HeaderField, 0),
	}

	// Parse format like <u32:sec><u32:usec><u32:length><u32>
	re := regexp.MustCompile(`<u(\d+)(?::([^>]+))?>`)
	matches := re.FindAllStringSubmatch(format, -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("no valid field specifications found")
	}

	for i, match := range matches {
		width, err := strconv.Atoi(match[1])
		if err != nil || (width != 16 && width != 32 && width != 64) {
			return nil, fmt.Errorf("invalid bit width: %s (must be 16, 32, or 64)", match[1])
		}

		field := HeaderField{
			Width: width,
			Type:  FieldIgnore,
		}

		if len(match) > 2 && match[2] != "" {
			typeStr := match[2]
			switch {
			case typeStr == "sec":
				field.Type = FieldSec
			case typeStr == "usec":
				field.Type = FieldUsec
			case typeStr == "nsec":
				field.Type = FieldNsec
			case typeStr == "length":
				field.Type = FieldLength
				result.HasLength = true
				result.LengthIndex = i
			case strings.HasPrefix(typeStr, "0x"):
				field.Type = FieldMagic
				val, err := strconv.ParseUint(typeStr[2:], 16, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid hex value: %s", typeStr)
				}
				field.MagicValue = val
			default:
				return nil, fmt.Errorf("unknown field type: %s", typeStr)
			}
		}

		result.Fields = append(result.Fields, field)
		result.TotalBytes += width / 8
	}

	return result, nil
}

func (fb *FileBuffer) run() error {
	defer fb.closeCurrentFile()

	buf := make([]byte, 32*1024) // 32KB buffer for reading
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			if writeErr := fb.write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading from stdin: %w", err)
		}
	}

	return nil
}

func (fb *FileBuffer) write(data []byte) error {
	// Capture header from first data if needed
	if !fb.headerCaptured && fb.headerBytes > 0 {
		bytesToCapture := fb.headerBytes
		if bytesToCapture > len(data) {
			bytesToCapture = len(data)
		}
		fb.header = make([]byte, bytesToCapture)
		copy(fb.header, data[:bytesToCapture])
		fb.headerCaptured = true
		fmt.Fprintf(os.Stderr, "Captured %d header bytes from stream\n", bytesToCapture)
	}

	// Add data to pending buffer if we're searching for block boundary
	if len(fb.pendingData) > 0 {
		fb.pendingData = append(fb.pendingData, data...)
		return fb.flushPendingData()
	}

	for len(data) > 0 {
		// Open new file if needed (both file and gzip writer must be nil)
		if fb.currentFile == nil || fb.gzipWriter == nil {
			if err := fb.openNewFile(); err != nil {
				return err
			}
			
			// Write header to new file (except for the very first file which already has it)
			if fb.fileCounter > 1 && len(fb.header) > 0 {
				if _, err := fb.gzipWriter.Write(fb.header); err != nil {
					return fmt.Errorf("writing header to new file: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Wrote %d header bytes to file\n", len(fb.header))
			}
		}
		
		// Flush to ensure data is written to file
		if err := fb.gzipWriter.Flush(); err != nil {
			return fmt.Errorf("flushing gzip writer: %w", err)
		}

		// Check actual file size on disk
		fileInfo, err := fb.currentFile.Stat()
		if err != nil {
			return fmt.Errorf("getting file stats: %w", err)
		}

		// Check if we need to start looking for block boundary
		if fileInfo.Size() >= fb.maxFileSize {
			if fb.blockFormat != nil {
				// Start buffering data to find block boundary
				fb.pendingData = append(fb.pendingData, data...)
				return fb.flushPendingData()
			} else {
				// No block format, just close immediately
				if err := fb.closeCurrentFile(); err != nil {
					return err
				}
			}
		}

		// Write data to gzip writer
		n, err := fb.gzipWriter.Write(data)
		if err != nil {
			return fmt.Errorf("writing to gzip: %w", err)
		}
		data = data[n:]
	}
	return nil
}

func (fb *FileBuffer) flushPendingData() error {
	// Try to find a valid block header in pending data
	if fb.blockFormat == nil {
		return fmt.Errorf("internal error: flushPendingData called without block format")
	}

	maxScanSize := fb.maxBlockSize + fb.blockFormat.TotalBytes
	
	// Search for valid block header
	for offset := 0; offset <= len(fb.pendingData)-fb.blockFormat.TotalBytes; offset++ {
		if blockLen, valid := fb.validateBlockHeader(fb.pendingData[offset:]); valid {
			// Found valid header! Write until end of this block
			endOfBlock := offset + fb.blockFormat.TotalBytes + blockLen
			
			if endOfBlock > len(fb.pendingData) {
				// Need more data to complete this block
				if len(fb.pendingData) > maxScanSize {
					// Scanned too far without finding complete block
					fmt.Fprintf(os.Stderr, "Warning: no complete block found within %d bytes, forcing rotation\n", maxScanSize)
					return fb.forceRotation()
				}
				// Wait for more data
				return nil
			}

			// Write everything up to and including this block
			if _, err := fb.gzipWriter.Write(fb.pendingData[:endOfBlock]); err != nil {
				return fmt.Errorf("writing pending data: %w", err)
			}

			// Close current file and start new one
			if err := fb.closeCurrentFile(); err != nil {
				return err
			}

			// Keep remaining data for next file
			fb.pendingData = fb.pendingData[endOfBlock:]
			
			// Continue writing remaining data
			if len(fb.pendingData) > 0 {
				remaining := fb.pendingData
				fb.pendingData = nil
				return fb.write(remaining)
			}
			
			fb.pendingData = nil
			return nil
		}
	}

	// No valid header found yet
	if len(fb.pendingData) > maxScanSize {
		fmt.Fprintf(os.Stderr, "Warning: no valid block header found within %d bytes, forcing rotation\n", maxScanSize)
		return fb.forceRotation()
	}

	// Wait for more data
	return nil
}

func (fb *FileBuffer) forceRotation() error {
	// Write all pending data and rotate
	if len(fb.pendingData) > 0 {
		if _, err := fb.gzipWriter.Write(fb.pendingData); err != nil {
			return fmt.Errorf("writing pending data on forced rotation: %w", err)
		}
	}
	fb.pendingData = nil
	return fb.closeCurrentFile()
}

func (fb *FileBuffer) validateBlockHeader(data []byte) (int, bool) {
	if len(data) < fb.blockFormat.TotalBytes {
		return 0, false
	}

	now := time.Now().Unix()
	offset := 0
	blockLength := 0

	for i, field := range fb.blockFormat.Fields {
		var value uint64
		
		switch field.Width {
		case 16:
			if offset+2 > len(data) {
				return 0, false
			}
			value = uint64(binary.LittleEndian.Uint16(data[offset:]))
			offset += 2
		case 32:
			if offset+4 > len(data) {
				return 0, false
			}
			value = uint64(binary.LittleEndian.Uint32(data[offset:]))
			offset += 4
		case 64:
			if offset+8 > len(data) {
				return 0, false
			}
			value = binary.LittleEndian.Uint64(data[offset:])
			offset += 8
		}

		// Validate based on field type
		switch field.Type {
		case FieldSec:
			// Within ±48 hours
			diff := int64(value) - now
			if diff < -48*3600 || diff > 48*3600 {
				return 0, false
			}
		case FieldUsec:
			if value > 999999 {
				return 0, false
			}
		case FieldNsec:
			if value > 999999999 {
				return 0, false
			}
		case FieldLength:
			if value > uint64(fb.maxBlockSize) {
				return 0, false
			}
			blockLength = int(value)
		case FieldMagic:
			if value != field.MagicValue {
				return 0, false
			}
		case FieldIgnore:
			// Any value is okay
		}

		// Store length if this is the length field
		if i == fb.blockFormat.LengthIndex && fb.blockFormat.HasLength {
			blockLength = int(value)
		}
	}

	return blockLength, true
}

func (fb *FileBuffer) openNewFile() error {
	// Delete oldest file if we've reached the limit
	if len(fb.activeFiles) >= fb.maxNumFiles {
		oldestFile := fb.activeFiles[0]
		if err := os.Remove(oldestFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing oldest file %s: %w", oldestFile, err)
		}
		fb.activeFiles = fb.activeFiles[1:]
	}

	// Generate filename
	filename := fb.generateFilename()

	// Create file
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("creating file %s: %w", filename, err)
	}

	// Store file handle and create NEW gzip writer for this file
	fb.currentFile = f
	fb.gzipWriter = gzip.NewWriter(f) // Creates a fresh gzip writer with new header
	fb.currentSize = 0
	fb.fileCounter++
	fb.activeFiles = append(fb.activeFiles, filename)

	fmt.Fprintf(os.Stderr, "Created new file: %s (counter: %d)\n", filename, fb.fileCounter)

	return nil
}

func (fb *FileBuffer) closeCurrentFile() error {
	if fb.gzipWriter == nil {
		return nil
	}

	// Close gzip writer first to flush compressed data
	if err := fb.gzipWriter.Close(); err != nil {
		fb.currentFile.Close()
		return fmt.Errorf("closing gzip writer: %w", err)
	}

	// Close the file
	if err := fb.currentFile.Close(); err != nil {
		return fmt.Errorf("closing file: %w", err)
	}

	fb.gzipWriter = nil
	fb.currentFile = nil
	return nil
}

func (fb *FileBuffer) generateFilename() string {
	timestamp := time.Now().UTC().Format(fb.timeFormat)
	
	// Split prefix into name and extension
	ext := filepath.Ext(fb.filePrefix)
	nameWithoutExt := strings.TrimSuffix(fb.filePrefix, ext)
	
	// Create filename with zero-padded counter
	// Using 6 digits for counter to support large rotations
	if ext != "" {
		return fmt.Sprintf("%s_%06d_%s%s.gz", nameWithoutExt, fb.fileCounter, timestamp, ext)
	}
	return fmt.Sprintf("%s_%06d_%s.gz", fb.filePrefix, fb.fileCounter, timestamp)
}

// Load existing files matching the pattern and initialize counter
func (fb *FileBuffer) loadExistingFiles() error {
	// Build regex pattern for matching files
	ext := filepath.Ext(fb.filePrefix)
	nameWithoutExt := strings.TrimSuffix(fb.filePrefix, ext)
	escapedName := regexp.QuoteMeta(nameWithoutExt)
	
	var pattern string
	if ext != "" {
		escapedExt := regexp.QuoteMeta(ext)
		pattern = fmt.Sprintf(`^%s_(\d{6})_.*%s\.gz$`, escapedName, escapedExt)
	} else {
		pattern = fmt.Sprintf(`^%s_(\d{6})_.*\.gz$`, escapedName)
	}
	
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("compiling regex pattern: %w", err)
	}

	// Get directory and base name for globbing
	dir := filepath.Dir(fb.filePrefix)
	if dir == "." || dir == "" {
		dir = "."
	}

	// Read directory entries
	entries, err := os.ReadDir(dir)
	if err != nil {
		// If directory doesn't exist, that's okay - no files to load
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading directory: %w", err)
	}

	// Find and parse matching files
	type fileInfo struct {
		path    string
		counter int
	}
	var matchedFiles []fileInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		filename := entry.Name()
		if !re.MatchString(filename) {
			continue
		}

		// Extract counter from filename
		matches := re.FindStringSubmatch(filename)
		if len(matches) < 2 {
			continue
		}

		counter, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}

		fullPath := filepath.Join(dir, filename)
		matchedFiles = append(matchedFiles, fileInfo{
			path:    fullPath,
			counter: counter,
		})
	}

	// Sort by counter
	sort.Slice(matchedFiles, func(i, j int) bool {
		return matchedFiles[i].counter < matchedFiles[j].counter
	})

	// Delete excess files if more than maxNumFiles
	if len(matchedFiles) > fb.maxNumFiles {
		filesToDelete := matchedFiles[:len(matchedFiles)-fb.maxNumFiles]
		for _, f := range filesToDelete {
			if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Warning: failed to delete excess file %s: %v\n", f.path, err)
			}
		}
		matchedFiles = matchedFiles[len(matchedFiles)-fb.maxNumFiles:]
	}

	// Populate activeFiles
	fb.activeFiles = make([]string, 0, len(matchedFiles))
	for _, f := range matchedFiles {
		fb.activeFiles = append(fb.activeFiles, f.path)
	}

	// Initialize counter to continue from highest existing counter
	if len(matchedFiles) > 0 {
		fb.fileCounter = matchedFiles[len(matchedFiles)-1].counter + 1
	}

	if len(fb.activeFiles) > 0 {
		fmt.Fprintf(os.Stderr, "Loaded %d existing file(s), resuming from counter %d\n",
			len(fb.activeFiles), fb.fileCounter)
	}

	return nil
}
