// feedparser.go -- routines to parse txt and json records from a
//                  URL
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2

package blacklist

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Fetch URL and write contents to chan 'ch'
func (d *Builder) fetchURL(u string, ch chan string, isJson bool) {

	defer close(ch)

	var rfd io.Reader
	var wfd io.Writer
	var cstr string

	// We cache data for a day and not fetch everytime.
	fd, cached, err := d.maybeCached(u)
	if err != nil {
		d.Lock()
		d.errs = append(d.errs, fmt.Errorf("cache: %s: %s", u, err))
		d.Unlock()

		return
	}

	defer fd.Close()
	if !cached {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			d.Lock()
			defer d.Unlock()

			d.errs = append(d.errs, fmt.Errorf("GET %s: %s", u, err))
			return
		}

		dia := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 0 * time.Second,
		}

		cli := &http.Client{
			Transport: &http.Transport{
				Dial:                dia.Dial,
				TLSHandshakeTimeout: 8 * time.Second,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     10 * time.Second,
			},
		}

		resp, err := cli.Do(req)
		if err != nil {
			d.Lock()
			d.errs = append(d.errs, fmt.Errorf("GET %s: %s", u, err))
			defer d.Unlock()

			return
		}

		defer resp.Body.Close()
		wfd = fd
		rfd = resp.Body
		cstr = "+fetch"
	} else {
		rfd = fd
		wfd = nil
		cstr = "+cache"
	}

	var n int
	if isJson {
		n = jsonIO(rfd, ch, wfd)
	} else {
		n = textIO(rfd, ch, wfd)
	}

	d.progress("%48.48s: %d entries [%s]", u, n, cstr)
}

// Return data from the cache if it is not stale, else create the
// file for caching
func (d *Builder) maybeCached(u string) (*os.File, bool, error) {
	var nm string = u

	csum := sha256.Sum256([]byte(u))
	sum := csum[:10]
	if strings.HasPrefix(u, "http://") {
		nm = u[7:]
	} else if strings.HasPrefix(u, "https://") {
		nm = u[8:]
	}

	if i := strings.Index(nm, "/"); i > 0 {
		nm = nm[:i]
	}

	fn := fmt.Sprintf("%s/.%s-%x", d.cachedir, nm, sum)
	fd, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE, 0640)
	if err != nil {
		return nil, false, err
	}

	fi, err := fd.Stat()
	if err != nil {
		return nil, false, err
	}

	now := time.Now()
	if fi.Size() > 0 && now.Sub(fi.ModTime()) < (24*time.Hour) {
		return fd, true, nil
	}

	fmt.Fprintf(fd, "# %s\n", u)
	return fd, false, nil
}

func isIP4(s string) bool {
	if ii := net.ParseIP(s); ii != nil {
		if ii = ii.To4(); ii != nil {
			return true
		}
	}
	return false
}

// Read from 'fd' and write to channel 'ch'; optionally save to 'wrfd' if it
// is non-nil.
//
// If 'fd' is a URL, it is assumed to contain lines of the following form:
//   - # ...
//   - IP   hostname
//   - hostname
func textIO(rd io.Reader, ch chan string, wrfd io.Writer) int {
	var s string

	if wrfd != nil {
		tee := io.TeeReader(rd, wrfd)
		rd = tee
	}

	r := bufio.NewScanner(rd)
	n := 0
	for r.Scan() {
		n += 1
		s = strings.TrimSpace(r.Text())
		if len(s) == 0 || s[0] == '#' {
			continue
		}

		v := strings.Fields(s)
		n += 1
		switch len(v) {
		case 1: // plain hostname
			ch <- v[0]

		// this can be one of:
		//    ip  hostname [garbage..]
		//    hostname [garbage ..]
		default:
			v0 := v[0]
			if isIP4(v0) {
				v0 = v[1]
			}
			ch <- v0
		}
	}

	return n
}

type tracker struct {
	Domain string `json:"domain"`
}

type trackerList struct {
	Domains []tracker
}

func jsonIO(rd io.Reader, ch chan string, wrfd io.Writer) int {

	if wrfd != nil {
		tee := io.TeeReader(rd, wrfd)
		rd = tee
	}

	jj := json.NewDecoder(rd)

	_, e := jj.Token() // consume '['
	if e != nil {
		return 0
	}

	n := 0
	for jj.More() {
		var d tracker
		e := jj.Decode(&d)
		if e == nil {
			n += 1
			ch <- d.Domain
		}
	}

	return n
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
