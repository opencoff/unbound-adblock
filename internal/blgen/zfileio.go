// openfile.go -- file opener that handles gzipped files in a clean
// way.
//
// Implements the io.ReadCloser interface
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2

package blgen

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"
)

// Uniformly open a compressed file or a regular file
func OpenFileRO(fn string) (io.ReadCloser, error) {
	var fd io.ReadCloser
	var err error

	zfd, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	if strings.HasSuffix(fn, ".gz") {
		gfd, err := gzip.NewReader(zfd)
		if err != nil {
			return nil, fmt.Errorf("can't read gz file: %s", err)
		}

		fd = &rcloser{fd: zfd, zfd: gfd}
	} else {
		fd = zfd
	}

	return fd, nil
}

// Stacked reader-closer to close both open files
// Needed for opening compress/xxxx files
type rcloser struct {
	fd  *os.File      // outer file
	zfd io.ReadCloser // inner file
}

// satisfies the Reader interface
func (r *rcloser) Read(b []byte) (int, error) {
	return r.zfd.Read(b)
}

// satisfies the Closer interface
// XXX Can only report one error
func (r *rcloser) Close() error {
	err := r.zfd.Close()
	if err != nil {
		r.fd.Close() // XXX We ignore this?
		return err
	}

	return r.fd.Close()
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
