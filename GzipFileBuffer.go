package main

import (
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

type Endianness int

const (
	LittleEndian Endianness = iota
	BigEndian
)

type HeaderField struct {
	Width      int // 8, 16, 32, 64 bits
	Type       FieldType
	MagicValue uint64 // For magic number fields
	Signed     bool   // For signed vs unsigned interpretation
}

type BlockHeaderFormat struct {
	Fields      []HeaderField
	TotalBytes  int
	HasLength   bool
	LengthIndex int
	Endianness  Endianness
}

type FileBuffer struct {
	filePrefix       string
	maxFileSize      int64
	maxNumFiles      int
	timeFormat       string
	useLocalTime     bool
	headerBytes      int
	header           []byte
	headerCaptured   bool
	blockFormat      *BlockHeaderFormat
	maxBlockSize     int
	readBufferSize   int
	compressionLevel int
	currentFile      *os.File
	gzipWriter       *gzip.Writer
	fileCounter      int
	activeFiles      []string
}

func main() {
	fileSizeKB := flag.Int64("file_size", 0, "Maximum size per file in kilobytes (required)")
	numFiles := flag.Int("num_files", 0, "Maximum number of files to keep (required)")
	filePrefix := flag.String("file_prefix", "", "Prefix for output files (required)")
	timeFormat := flag.String("time_format", "2006-01-02T15:04:05.000Z", "Time format for filenames (Go time layout)")
	useLocalTime := flag.Bool("local_time", false, "Use local time instead of UTC for timestamps")
	headerBytes := flag.Int("header_bytes", 0, "Number of bytes from start of stream to copy as header for each file (default: 0)")
	blockHeader := flag.String("block_header", "", "Block header format for boundary detection (e.g., <u32:sec><u32:usec><u32:length><u32>)")
	maxBlockSize := flag.Int("max_block_size", 262144, "Maximum block size in bytes when scanning for boundaries (default: 262144 / 256KB)")
	readBufferSize := flag.Int("read_buffer_size", 262144, "Read buffer size in bytes (default: 262144 / 256KB)")
	compressionLevel := flag.Int("compression_level", gzip.DefaultCompression, "Gzip compression level: -1 (default), 0 (none), 1 (best speed) to 9 (best compression)")
	endianness := flag.String("endianness", "little", "Byte order for multi-byte fields: 'little' or 'big' (default: little)")
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
		fmt.Fprintf(os.Stderr, "  cat video.mp4 | %s --file_size 102400 --num_files 5 --file_prefix video.mp4 --header_bytes 1024 --compression_level 1\n", os.Args[0])
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
		fmt.Fprintf(os.Stderr, "  Format: <uN:type> or <sN:type> where N is bit width (8, 16, 32, 64)\n")
		fmt.Fprintf(os.Stderr, "  Use 'u' for unsigned, 's' for signed. Types:\n")
		fmt.Fprintf(os.Stderr, "    sec     - Unix timestamp seconds (validated within ±48 hours)\n")
		fmt.Fprintf(os.Stderr, "    usec    - Microseconds (0-999999)\n")
		fmt.Fprintf(os.Stderr, "    nsec    - Nanoseconds (0-999999999)\n")
		fmt.Fprintf(os.Stderr, "    length  - Block data length in bytes (0-%d, configurable with --max_block_size)\n", 262144)
		fmt.Fprintf(os.Stderr, "    0xHEX   - Magic number (exact match required)\n")
		fmt.Fprintf(os.Stderr, "    (none)  - Any value (ignored)\n")
		fmt.Fprintf(os.Stderr, "  Example for pcap: <u32:sec><u32:usec><u32:length><u32>\n")
		fmt.Fprintf(os.Stderr, "  Example with 8-bit: <u8:0xAA><u8:0xBB><u16:length><u32>\n")
		fmt.Fprintf(os.Stderr, "  Endianness controlled by --endianness flag (default: little).\n")
		fmt.Fprintf(os.Stderr, "  Note: Endianness does not apply to 8-bit fields.\n\n")
		fmt.Fprintf(os.Stderr, "Compression Level:\n")
		fmt.Fprintf(os.Stderr, "  -1: Default compression (balanced)\n")
		fmt.Fprintf(os.Stderr, "   0: No compression (fastest, largest files)\n")
		fmt.Fprintf(os.Stderr, "   1: Best speed (fast, larger files)\n")
		fmt.Fprintf(os.Stderr, "   9: Best compression (slow, smallest files)\n\n")
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
	if *readBufferSize <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --read_buffer_size must be positive")
		os.Exit(1)
	}
	if *compressionLevel < -1 || *compressionLevel > 9 {
		fmt.Fprintln(os.Stderr, "Error: --compression_level must be between -1 and 9")
		os.Exit(1)
	}

	// Validate endianness
	var byteOrder Endianness
	switch strings.ToLower(*endianness) {
	case "little":
		byteOrder = LittleEndian
	case "big":
		byteOrder = BigEndian
	default:
		fmt.Fprintf(os.Stderr, "Error: --endianness must be 'little' or 'big', got: %s\n", *endianness)
		os.Exit(1)
	}

	// Validate header size vs read buffer size
	if *headerBytes > *readBufferSize {
		fmt.Fprintln(os.Stderr, "Error: --read_buffer_size must be at least as large as --header_bytes")
		os.Exit(1)
	}

	// Validate max block size vs read buffer size
	if *maxBlockSize > *readBufferSize {
		fmt.Fprintln(os.Stderr, "Error: --read_buffer_size must be at least as large as --max_block_size")
		os.Exit(1)
	}

	fb := &FileBuffer{
		filePrefix:       *filePrefix,
		maxFileSize:      *fileSizeKB * 1024, // Convert KB to bytes
		maxNumFiles:      *numFiles,
		timeFormat:       *timeFormat,
		useLocalTime:     *useLocalTime,
		headerBytes:      *headerBytes,
		maxBlockSize:     *maxBlockSize,
		readBufferSize:   *readBufferSize,
		compressionLevel: *compressionLevel,
		activeFiles:      make([]string, 0, *numFiles),
	}

	// Parse block header format if provided
	if *blockHeader != "" {
		fb.blockFormat = parseBlockHeaderFormat(*blockHeader, byteOrder)
		endianStr := "little-endian"
		if byteOrder == BigEndian {
			endianStr = "big-endian"
		}
		fmt.Fprintf(os.Stderr, "Block header format: %d bytes, %d fields (%s)\n", fb.blockFormat.TotalBytes, len(fb.blockFormat.Fields), endianStr)
	}

	// Resume from existing files if requested
	if *resumeExisting {
		fb.loadExistingFiles()
	}

	dataChannel := make(chan []byte, 100) //allow up to 100 reads per processor iteration
	var wg sync.WaitGroup
	wg.Add(1)

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		fmt.Fprintf(os.Stderr, "Main: Received signal: %v. Initiating graceful shutdown...\n", sig)
		fmt.Fprintf(os.Stderr, "Main: Press Ctrl+C again to force exit (will lose unprocessed data).\n")
		os.Stdin.Close()
		<-sigChan
		fmt.Fprintf(os.Stderr, "Main: Received second signal. Forcing exit.\n")
		os.Exit(1)
	}()
	defer signal.Stop(sigChan)

	// Let's go!
	fb.openNewFile()
	go processor(dataChannel, fb, &wg)
	go reader(dataChannel, *readBufferSize)
	wg.Wait()
	fb.closeCurrentFile()
	fmt.Fprintf(os.Stderr, "Main: Shutdown cleanly.\n")
}

// "producer" goroutine.
// It reads data from os.Stdin as fast as possible and sends it to the dataChannel.
func reader(dataChannel chan<- []byte, maxsize int) {
	defer close(dataChannel)

	readBuffer := make([]byte, maxsize)

	for {
		n, err := os.Stdin.Read(readBuffer)
		if n > 0 {
			// Copy the read data to a new slice to avoid overwriting
			// in the next read.
			dataToSend := make([]byte, n)
			copy(dataToSend, readBuffer[:n])

			// Send the copied data to the processor
			dataChannel <- dataToSend
		}

		// Handle errors
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			}
			break // Exit loop on EOF or any error
		}
	}
}

// "consumer" goroutine.
// It receives data from the dataChannel, buffers it, and processes it in chunks
func processor(dataChannel <-chan []byte, fb *FileBuffer, wg *sync.WaitGroup) {
	defer wg.Done()

	var processingBuffer []byte

	// This 'for range' loop will automatically run until the
	// dataChannel is closed (by the reader) and empty.
	for receivedData := range dataChannel {
		processingBuffer = append(processingBuffer, receivedData...)

		// Process once there's more than a chunk available
		for len(processingBuffer) >= fb.readBufferSize {
			// extract the chunk to process
			chunk := processingBuffer[:fb.readBufferSize]
			processingBuffer = processingBuffer[fb.readBufferSize:]

			fb.write(chunk)
		}
	}

	// After the channel is closed, there might be some data left
	if len(processingBuffer) > 0 {
		fmt.Fprintf(os.Stderr, "Processing final %d bytes of data\n", len(processingBuffer))
		fb.write(processingBuffer)
	}
}

func parseBlockHeaderFormat(format string, endianness Endianness) *BlockHeaderFormat {
	result := &BlockHeaderFormat{
		Fields:     make([]HeaderField, 0),
		Endianness: endianness,
	}

	// Parse format like <u32:sec><u32:usec><u32:length><u32> or <s16:value> or <u8:0xFF>
	re := regexp.MustCompile(`<([us])(\d+)(?::([^>]+))?>`)
	matches := re.FindAllStringSubmatch(format, -1)

	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Invalid block header format: %s\n", format)
		os.Exit(1)
	}

	for i, match := range matches {
		signedness := match[1]
		width, err := strconv.Atoi(match[2])
		if err != nil || (width != 8 && width != 16 && width != 32 && width != 64) {
			fmt.Fprintf(os.Stderr, "Error: Invalid field width: %s\n", match[2])
			os.Exit(1)
		}

		field := HeaderField{
			Width:  width,
			Type:   FieldIgnore,
			Signed: signedness == "s",
		}

		if len(match) > 3 && match[3] != "" {
			typeStr := match[3]
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
					fmt.Fprintf(os.Stderr, "Error: Invalid magic number: %s\n", typeStr)
					os.Exit(1)
				}
				field.MagicValue = val
			default:
				fmt.Fprintf(os.Stderr, "Error: Unknown field type: %s\n", typeStr)
				os.Exit(1)
			}
		}

		result.Fields = append(result.Fields, field)
		result.TotalBytes += width / 8
	}

	return result
}

func (fb *FileBuffer) write(data []byte) {
	// Capture header from first data if needed
	if !fb.headerCaptured && fb.headerBytes > 0 {
		bytesToCapture := fb.headerBytes
		if len(data) < fb.headerBytes {
			fmt.Fprintf(os.Stderr, "Insufficient data to capture header: need %d bytes, got %d bytes", fb.headerBytes, len(data))
			bytesToCapture = len(data)
		}

		fb.header = make([]byte, bytesToCapture)
		copy(fb.header, data[:bytesToCapture])
		fb.headerCaptured = true

		fmt.Fprintf(os.Stderr, "Captured %d header bytes from stream\n", fb.headerBytes)
	}

	// Flush to ensure data is written to file
	if err := fb.gzipWriter.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Flushing gzip writer: %w", err)
	}

	// Check actual file size on disk
	fileInfo, err := fb.currentFile.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Getting file stats: %w", err)
	}

	// Check for rotate condition before writing new data
	if fileInfo.Size() >= fb.maxFileSize {
		nextBlockOffset := int(0)
		if fb.blockFormat != nil {
			nextBlockOffset = fb.findBlockHeader(data)
		}
		//write up to nextBlockOffset and rotate
		n, err := fb.gzipWriter.Write(data[:nextBlockOffset])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Writing to gzip: %w", err)
		}
		if n != nextBlockOffset {
			fmt.Fprintf(os.Stderr, "Short write to gzip: wrote %d bytes, expected %d bytes", n, nextBlockOffset)
		}
		fb.closeCurrentFile()
		data = data[n:]
		fb.openNewFile()
	}

	// Write data to gzip writer
	n, err := fb.gzipWriter.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Writing to gzip: %w", err)
	}
	if n != len(data) {
		fmt.Fprintf(os.Stderr, "Short write to gzip: wrote %d bytes, expected %d bytes", n, len(data))
	}
}

func (fb *FileBuffer) findBlockHeader(data []byte) int {
	if fb.blockFormat == nil {
		fmt.Fprintf(os.Stderr, "Internal error: findBlockHeader called without block format")
		return len(data)
	}

	// Search for valid block header
	for offset := 0; offset <= len(data)-fb.blockFormat.TotalBytes; offset++ {
		if valid := fb.validateBlockHeader(data[offset:]); valid {
			return offset
		}
	}

	fmt.Fprintf(os.Stderr, "Warning: no valid block header found (to split on) in read buffer. Try a bigger buffer?\n")
	return len(data)
}

func (fb *FileBuffer) validateBlockHeader(data []byte) bool {
	if len(data) < fb.blockFormat.TotalBytes {
		return false
	}

	now := time.Now().Unix()
	offset := 0

	for _, field := range fb.blockFormat.Fields {
		var value uint64

		switch field.Width {
		case 8:
			if offset+1 > len(data) {
				return false
			}
			value = uint64(data[offset])
			offset += 1
		case 16:
			if offset+2 > len(data) {
				return false
			}
			if fb.blockFormat.Endianness == LittleEndian {
				value = uint64(binary.LittleEndian.Uint16(data[offset:]))
			} else {
				value = uint64(binary.BigEndian.Uint16(data[offset:]))
			}
			offset += 2
		case 32:
			if offset+4 > len(data) {
				return false
			}
			if fb.blockFormat.Endianness == LittleEndian {
				value = uint64(binary.LittleEndian.Uint32(data[offset:]))
			} else {
				value = uint64(binary.BigEndian.Uint32(data[offset:]))
			}
			offset += 4
		case 64:
			if offset+8 > len(data) {
				return false
			}
			if fb.blockFormat.Endianness == LittleEndian {
				value = binary.LittleEndian.Uint64(data[offset:])
			} else {
				value = binary.BigEndian.Uint64(data[offset:])
			}
			offset += 8
		}

		// Validate based on field type
		switch field.Type {
		case FieldSec:
			// Within ±48 hours
			diff := int64(value) - now
			if diff < -48*3600 || diff > 48*3600 {
				return false
			}
		case FieldUsec:
			if value > 999999 {
				return false
			}
		case FieldNsec:
			if value > 999999999 {
				return false
			}
		case FieldLength:
			if value > uint64(fb.maxBlockSize) {
				return false
			}
		case FieldMagic:
			if value != field.MagicValue {
				return false
			}
		case FieldIgnore:
			// Any value is okay
		}
	}

	return true
}

func (fb *FileBuffer) openNewFile() {
	// Delete oldest file if we've reached the limit
	if len(fb.activeFiles) >= fb.maxNumFiles {
		oldestFile := fb.activeFiles[0]
		if err := os.Remove(oldestFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: failed to delete oldest file %s: %v\n", oldestFile, err)
		} else {
			fmt.Fprintf(os.Stderr, "Deleted oldest file: %s\n", oldestFile)
		}
		fb.activeFiles = fb.activeFiles[1:]
	}

	// Generate filename
	filename := fb.generateFilename()

	// Create file
	f, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating file %s: %w", filename, err)
		os.Exit(1)
	}

	// Store file handle and create NEW gzip writer for this file with specified compression level
	fb.currentFile = f
	gzWriter, err := gzip.NewWriterLevel(f, fb.compressionLevel)
	if err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "Creating gzip writer for file %s: %w", filename, err)
		os.Exit(1)
	}
	fb.gzipWriter = gzWriter
	fb.fileCounter++
	fb.activeFiles = append(fb.activeFiles, filename)

	fmt.Fprintf(os.Stderr, "Created new file: %s (counter: %d, compression: %d)\n", filename, fb.fileCounter, fb.compressionLevel)

	// Write header to new files if it's been captured
	if fb.headerCaptured && fb.headerBytes > 0 {
		if _, err := fb.gzipWriter.Write(fb.header); err != nil {
			fmt.Fprintf(os.Stderr, "Writing header to file %s: %w", filename, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Wrote %d header bytes to file\n", len(fb.header))
	}
}

func (fb *FileBuffer) closeCurrentFile() {
	if fb.gzipWriter == nil && fb.currentFile == nil {
		return
	}

	// Close gzip writer first to flush compressed data
	if fb.gzipWriter != nil {
		if err := fb.gzipWriter.Close(); err != nil {
			if fb.currentFile != nil {
				fb.currentFile.Close()
			}
			fmt.Fprintf(os.Stderr, "Closing gzip writer: %w", err)
		}
		fb.gzipWriter = nil
	}

	// Close the file
	if fb.currentFile != nil {
		if err := fb.currentFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Closing file: %w", err)
		}
		fb.currentFile = nil
	}
}

func (fb *FileBuffer) generateFilename() string {
	var timestamp string
	if fb.useLocalTime {
		timestamp = time.Now().Local().Format(fb.timeFormat)
	} else {
		timestamp = time.Now().UTC().Format(fb.timeFormat)
	}

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
func (fb *FileBuffer) loadExistingFiles() {
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
		fmt.Fprintf(os.Stderr, "Compiling regex pattern: %w", err)
		return
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
			return
		}
		fmt.Fprintf(os.Stderr, "Reading directory %s: %w", dir, err)
		return
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
}
