package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileBuffer struct {
	filePrefix    string
	maxFileSize   int64
	maxNumFiles   int
	currentFile   *os.File
	gzipWriter    *gzip.Writer
	currentSize   int64
	fileCounter   int
	activeFiles   []string
}

func main() {
	fileSize := flag.Int64("file_size", 10*1024*1024, "Maximum size per file in bytes")
	numFiles := flag.Int("num_files", 5, "Maximum number of files to keep")
	filePrefix := flag.String("file_prefix", "output", "Prefix for output files")
	flag.Parse()

	if *fileSize <= 0 {
		fmt.Fprintln(os.Stderr, "Error: file_size must be positive")
		os.Exit(1)
	}
	if *numFiles <= 0 {
		fmt.Fprintln(os.Stderr, "Error: num_files must be positive")
		os.Exit(1)
	}

	fb := &FileBuffer{
		filePrefix:  *filePrefix,
		maxFileSize: *fileSize,
		maxNumFiles: *numFiles,
		activeFiles: make([]string, 0, *numFiles),
	}

	if err := fb.run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
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
	for len(data) > 0 {
		// Open new file if needed
		if fb.gzipWriter == nil {
			if err := fb.openNewFile(); err != nil {
				return err
			}
		}

		// Calculate how much we can write to current file
		remaining := fb.maxFileSize - fb.currentSize
		toWrite := int64(len(data))
		if toWrite > remaining {
			toWrite = remaining
		}

		// Write data
		n, err := fb.gzipWriter.Write(data[:toWrite])
		if err != nil {
			return fmt.Errorf("writing to gzip: %w", err)
		}
		fb.currentSize += int64(n)
		data = data[toWrite:]

		// Close file if it reached max size
		if fb.currentSize >= fb.maxFileSize {
			if err := fb.closeCurrentFile(); err != nil {
				return err
			}
		}
	}
	return nil
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

	fb.currentFile = f
	fb.gzipWriter = gzip.NewWriter(f)
	fb.currentSize = 0
	fb.fileCounter++
	fb.activeFiles = append(fb.activeFiles, filename)

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
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	
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
