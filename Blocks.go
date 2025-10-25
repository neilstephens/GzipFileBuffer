// Copyright (c) 2025 Neil Stephens. All rights reserved.
// Use of this source code is governed by an MIT license that can be
// found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
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
