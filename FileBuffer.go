// Copyright (c) 2025 Neil Stephens. All rights reserved.
// Use of this source code is governed by an MIT license that can be
// found in the LICENSE file.

package main

import (
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
