package main

import (
	"compress/gzip"
	"encoding/binary"
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
	resumeExisting   bool
}

func main() {
	fb := processArgs()

	// Resume from existing files if requested
	if fb.resumeExisting {
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
	go reader(dataChannel, fb.readBufferSize)
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

func (fb *FileBuffer) write(data []byte) {
	// Capture header from first data if needed
	if !fb.headerCaptured && fb.headerBytes > 0 {
		bytesToCapture := fb.headerBytes
		if len(data) < fb.headerBytes {
			fmt.Fprintf(os.Stderr, "Error: Insufficient data to capture header: need %d bytes, got %d bytes", fb.headerBytes, len(data))
			bytesToCapture = len(data)
		}

		fb.header = make([]byte, bytesToCapture)
		copy(fb.header, data[:bytesToCapture])
		fb.headerCaptured = true

		fmt.Fprintf(os.Stderr, "Captured %d header bytes from stream\n", fb.headerBytes)
	}

	// Flush to ensure data is written to file
	if err := fb.gzipWriter.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "Error flushing gzip writer: %s", err.Error())
	}

	// Check actual file size on disk
	fileInfo, err := fb.currentFile.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting file stats: %s", err.Error())
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
			fmt.Fprintf(os.Stderr, "Error writing to gzip: %s", err.Error())
		}
		if n != nextBlockOffset {
			fmt.Fprintf(os.Stderr, "Error: short write to gzip: wrote %d bytes, expected %d bytes", n, nextBlockOffset)
		}
		fb.closeCurrentFile()
		data = data[n:]
		fb.openNewFile()
	}

	// Write data to gzip writer
	n, err := fb.gzipWriter.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to gzip: %s", err.Error())
	}
	if n != len(data) {
		fmt.Fprintf(os.Stderr, "Error: short write to gzip: wrote %d bytes, expected %d bytes", n, len(data))
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
		fmt.Fprintf(os.Stderr, "Error creating file %s: %s", filename, err.Error())
		os.Exit(1)
	}

	// Store file handle and create NEW gzip writer for this file with specified compression level
	fb.currentFile = f
	gzWriter, err := gzip.NewWriterLevel(f, fb.compressionLevel)
	if err != nil {
		f.Close()
		fmt.Fprintf(os.Stderr, "Error creating gzip writer for file %s: %s", filename, err.Error())
		os.Exit(1)
	}
	fb.gzipWriter = gzWriter
	fb.fileCounter++
	fb.activeFiles = append(fb.activeFiles, filename)

	fmt.Fprintf(os.Stderr, "Created new file: %s (counter: %d, compression: %d)\n", filename, fb.fileCounter, fb.compressionLevel)

	// Write header to new files if it's been captured
	if fb.headerCaptured && fb.headerBytes > 0 {
		if _, err := fb.gzipWriter.Write(fb.header); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing header to file %s: %s", filename, err.Error())
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
			fmt.Fprintf(os.Stderr, "Error closing gzip writer: %s", err.Error())
		}
		fb.gzipWriter = nil
	}

	// Close the file
	if fb.currentFile != nil {
		if err := fb.currentFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file: %s", err.Error())
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
		fmt.Fprintf(os.Stderr, "Error compiling regex pattern: %s", err.Error())
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
		fmt.Fprintf(os.Stderr, "Error reading directory %s: %s", dir, err.Error())
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
