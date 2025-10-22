package main

import (
	"compress/gzip"
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

type FileBuffer struct {
	filePrefix    string
	maxFileSize   int64
	maxNumFiles   int
	timeFormat    string
	currentFile   *os.File
	gzipWriter    *gzip.Writer
	currentSize   int64
	fileCounter   int
	activeFiles   []string
}

func main() {
	fileSizeKB := flag.Int64("file_size", 0, "Maximum size per file in kilobytes (required)")
	numFiles := flag.Int("num_files", 0, "Maximum number of files to keep (required)")
	filePrefix := flag.String("file_prefix", "", "Prefix for output files (required)")
	timeFormat := flag.String("time_format", "2006-01-02T15:04:05.000Z", "Time format for filenames (Go time layout)")
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
		fmt.Fprintf(os.Stderr, "  cat stream | %s --file_size 1024 --num_files 3 --file_prefix data --time_format 20060102-150405\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Time Format:\n")
		fmt.Fprintf(os.Stderr, "  Uses Go time layout format. Default is ISO 8601: 2006-01-02T15:04:05.000Z\n")
		fmt.Fprintf(os.Stderr, "  Common formats:\n")
		fmt.Fprintf(os.Stderr, "    ISO 8601:     2006-01-02T15:04:05.000Z\n")
		fmt.Fprintf(os.Stderr, "    Simple:       20060102-150405\n")
		fmt.Fprintf(os.Stderr, "    Unix seconds: (use custom script for epoch time)\n\n")
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

	fb := &FileBuffer{
		filePrefix:  *filePrefix,
		maxFileSize: *fileSizeKB * 1024, // Convert KB to bytes
		maxNumFiles: *numFiles,
		timeFormat:  *timeFormat,
		activeFiles: make([]string, 0, *numFiles),
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
		// Open new file if needed (both file and gzip writer must be nil)
		if fb.currentFile == nil || fb.gzipWriter == nil {
			if err := fb.openNewFile(); err != nil {
				return err
			}
		}

		// Write data to gzip writer
		n, err := fb.gzipWriter.Write(data)
		if err != nil {
			return fmt.Errorf("writing to gzip: %w", err)
		}
		data = data[n:]

		// Flush to ensure data is written to file
		if err := fb.gzipWriter.Flush(); err != nil {
			return fmt.Errorf("flushing gzip writer: %w", err)
		}

		// Check actual file size on disk
		fileInfo, err := fb.currentFile.Stat()
		if err != nil {
			return fmt.Errorf("getting file stats: %w", err)
		}

		// Close file if it reached max size and start a new one on next iteration
		if fileInfo.Size() >= fb.maxFileSize {
			if err := fb.closeCurrentFile(); err != nil {
				return err
			}
			// File and gzip writer are now nil, will be recreated on next loop iteration
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
		fb.fileCounter = matchedFiles[len(matchedFiles)-1].counter
	}

	if len(fb.activeFiles) > 0 {
		fmt.Fprintf(os.Stderr, "Loaded %d existing file(s), resuming from counter %d\n", 
			len(fb.activeFiles), fb.fileCounter)
	}

	return nil
}
