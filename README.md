# Gzip File Buffer

Ever used the tshark -b (ring buffer) option and wished it could be combined with the copress option? Well here's a tool for you.

```
tshark -F pcap -i any -w - | ./GzipFileBuffer --file_size 2048 --num_files 10 --header_bytes 24 --block_header "<u32:sec><u32:nsec><u32:length><u32>" --file_prefix test.pcap
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
