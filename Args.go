// Copyright (c) 2025 Neil Stephens. All rights reserved.
// Use of this source code is governed by an MIT license that can be
// found in the LICENSE file.

package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"os"
	"strings"
)

func processArgs() *FileBuffer {
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
	quiet := flag.Bool("quiet", false, "Suppress non-error output")

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
		resumeExisting:   *resumeExisting,
		quiet:            *quiet,
	}

	// Parse block header format if provided
	if *blockHeader != "" {
		fb.blockFormat = parseBlockHeaderFormat(*blockHeader, byteOrder)
		endianStr := "little-endian"
		if byteOrder == BigEndian {
			endianStr = "big-endian"
		}
		if !fb.quiet {
			fmt.Fprintf(os.Stderr, "Block header format: %d bytes, %d fields (%s)\n", fb.blockFormat.TotalBytes, len(fb.blockFormat.Fields), endianStr)
		}
	}

	return fb
}
