# Gzip File Buffer

Ever used the tshark -b (ring buffer) option and wished it could be combined with the compress option? Well here's a tool for you.

```
tshark -F pcap -i any -w - | ./GzipFileBuffer --file_size 102400 --num_files 10 --header_bytes 24 --block_header "<u32:sec><u32:nsec><u32:length><u32>" --file_prefix test.pcap
```

## Other uses

It's not specific to pcap. You can stream arbitrary data, tail logs, etc, etc. If it's a block based format, specify a custom block-header format like the pcap example above, and it will split the stream on a block boundary and copy the stream header bytes to each file (if specified). Or just specify file name, file size, and number of files and it will compress and write raw unadulterated data.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Build
```
go mod init GzipFileBuffer
go mod tidy
go build -ldflags "-s -w"
```

## $ ./GzipFileBuffer --help
```
GzipFileBuffer - Stream stdin to rotating gzip-compressed files

Usage: ./GzipFileBuffer [OPTIONS]

Reads binary data from stdin, compresses it with gzip, and writes to a series
of rotating files. When a file reaches the specified size, it closes and starts
a new one. Maintains a maximum number of files by deleting the oldest.

Options:
  -block_header string
        Block header format for boundary detection (e.g., <u32:sec><u32:usec><u32:length><u32>)
  -compression_level int
        Gzip compression level: -1 (default), 0 (none), 1 (best speed) to 9 (best compression) (default -1)
  -endianness string
        Byte order for multi-byte fields: 'little' or 'big' (default: little) (default "little")
  -file_prefix string
        Prefix for output files (required)
  -file_size int
        Maximum size per file in kilobytes (required)
  -header_bytes int
        Number of bytes from start of stream to copy as header for each file (default: 0)
  -local_time
        Use local time instead of UTC for timestamps
  -max_block_size int
        Maximum block size in bytes when scanning for boundaries (default: 262144 / 256KB) (default 262144)
  -num_files int
        Maximum number of files to keep (required)
  -read_buffer_size int
        Read buffer size in bytes (default: 262144 / 256KB) (default 262144)
  -resume_existing
        Resume with existing files (WARNING: may delete matching files if count exceeds num_files)
  -time_format string
        Time format for filenames (Go time layout) (default "2006-01-02T15:04:05.000Z")

Filename Format:
  prefix_NNNNNN_TIMESTAMP[.ext].gz
  where NNNNNN is a zero-padded counter

Examples:
  cat data.bin | ./GzipFileBuffer --file_size 10240 --num_files 5 --file_prefix output
  cat logs.txt | ./GzipFileBuffer --file_size 51200 --num_files 10 --file_prefix logs.txt
  cat stream | ./GzipFileBuffer --file_size 1024 --num_files 3 --file_prefix data --time_format 20060102-150405
  cat video.mp4 | ./GzipFileBuffer --file_size 102400 --num_files 5 --file_prefix video.mp4 --header_bytes 1024 --compression_level 1
  tcpdump -w - | ./GzipFileBuffer --file_size 102400 --num_files 10 --file_prefix capture.pcap --block_header '<u32:sec><u32:usec><u32:length><u32>'

Time Format:
  Uses Go time layout format. Default is ISO 8601: 2006-01-02T15:04:05.000Z
  Common formats:
    ISO 8601:     2006-01-02T15:04:05.000Z
    Simple:       20060102-150405

Header Bytes:
  Captures the first N bytes of the input stream and prepends them to each
  subsequent file (after the first). Useful for formats that require headers
  (e.g., video containers, serialization formats). Set to 0 to disable.

Block Header Format:
  Specifies block/packet boundary detection to avoid splitting mid-block.
  Format: <uN:type> or <sN:type> where N is bit width (8, 16, 32, 64)
  Use 'u' for unsigned, 's' for signed. Types:
    sec     - Unix timestamp seconds (validated within ±48 hours)
    usec    - Microseconds (0-999999)
    nsec    - Nanoseconds (0-999999999)
    length  - Block data length in bytes (0-262144, configurable with --max_block_size)
    0xHEX   - Magic number (exact match required)
    (none)  - Any value (ignored)
  Example for pcap: <u32:sec><u32:usec><u32:length><u32>
  Example with 8-bit: <u8:0xAA><u8:0xBB><u16:length><u32>
  Endianness controlled by --endianness flag (default: little).
  Note: Endianness does not apply to 8-bit fields.

Compression Level:
  -1: Default compression (balanced)
   0: No compression (fastest, largest files)
   1: Best speed (fast, larger files)
   9: Best compression (slow, smallest files)
```