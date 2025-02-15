package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"os"
)

type checksumAlgorithm int

const (
	checksumMD5 checksumAlgorithm = iota
	checksumCRC32
	checksumCRC32C
	checksumSHA1
	checksumSHA256
	checksumCRC64NVME
)

func newChecksumCalculator() *checksumCalculator {
	checksums := []hash.Hash{
		checksumMD5:       md5.New(),
		checksumCRC32:     crc32.New(crc32.MakeTable(crc32.IEEE)),
		checksumCRC32C:    crc32.New(crc32.MakeTable(crc32.Castagnoli)),
		checksumSHA1:      sha1.New(),
		checksumSHA256:    sha256.New(),
		checksumCRC64NVME: crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5)),
	}
	writer := make([]io.Writer, len(checksums))
	for i, h := range checksums {
		writer[i] = h
	}
	w := io.MultiWriter(writer...)

	return &checksumCalculator{
		Writer: w,
		csum:   checksums,
	}
}

type checksumCalculator struct {
	io.Writer
	csum []hash.Hash
}

func (c *checksumCalculator) Result(algo checksumAlgorithm) []byte {
	return c.csum[algo].Sum(nil)
}

func calcChecksum(path string) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	calc := newChecksumCalculator()
	_, err = io.Copy(calc, file)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ETag: %s\n", hex.EncodeToString(calc.Result(checksumMD5)))
	fmt.Printf("Content-MD5: %s\n", base64.StdEncoding.EncodeToString(calc.Result(checksumMD5)))
	fmt.Printf("x-amz-checksum-crc32: %s\n", base64.StdEncoding.EncodeToString(calc.Result(checksumCRC32)))
	fmt.Printf("x-amz-checksum-crc32c: %s\n", base64.StdEncoding.EncodeToString(calc.Result(checksumCRC32C)))
	fmt.Printf("x-amz-checksum-crc64nvme: %s\n", base64.StdEncoding.EncodeToString(calc.Result(checksumCRC64NVME)))
	fmt.Printf("x-amz-checksum-sha1: %s\n", base64.StdEncoding.EncodeToString(calc.Result(checksumSHA1)))
	fmt.Printf("x-amz-checksum-sha256: %s\n", base64.StdEncoding.EncodeToString(calc.Result(checksumSHA256)))
}

func main() {
	if len(os.Args) < 1 {
		fmt.Println("Error: input file is required")
		os.Exit(1)
	}

	calcChecksum(os.Args[1])
}
