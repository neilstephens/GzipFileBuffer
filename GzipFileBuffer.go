// Copyright (c) 2025 Neil Stephens. All rights reserved.
// Use of this source code is governed by an MIT license that can be
// found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

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
