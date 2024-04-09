// main.go -- dns blocklist host generator
//
// Author: Sudhi Herle <sw@herle.net>
// License GPLv2

package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/opencoff/unbound-adblock/internal/blgen"

	flag "github.com/opencoff/pflag"
)

// basename of the program
var Z string = path.Base(os.Args[0])

// Controls global verbosity
var Verbose bool

func Progress(s string, v ...interface{}) {
	if !Verbose {
		return
	}

	if n := len(s); s[n-1] != '\n' {
		s += "\n"
	}
	s = fmt.Sprintf(s, v...)
	os.Stderr.WriteString(s)
	os.Stderr.Sync()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	flag.SetInterspersed(true)

	var feed string
	var wl []string
	var cachedir string
	var nocache bool
	var wlout string

	output := make(map[string]string)

	outfp := map[string]func(b *blgen.BL, fd io.Writer){
		"text":    textOut,
		"unbound": unboundOut,
		"txt":     textOut,
		"unb":     unboundOut,
	}

	// default output is text
	output["text"] = "-"

	flag.BoolVarP(&nocache, "no-cache", "", false, "Ignore the cached blocklist")
	flag.BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output")
	flag.StringVarP(&feed, "feed", "F", "", "Read blocklist URLs from feed file `F`")
	flag.StringSliceVarP(&wl, "allowlist", "W", []string{}, "Add allowlist entries from file `F`")

	flag.StringToStringVarP(&output, "output", "o", output, "Write outputs in the given formats")

	flag.StringVarP(&cachedir, "cache-dir", "c", ".", "Use `D` as the cache directory")
	flag.StringVarP(&wlout, "output-allowlist", "", "", "Write allowlist output to `F`")

	flag.Usage = func() {
		fmt.Printf(`Usage: %s [options] [blocklist ...]

Read one or more blocklist files and generate a composite file containing
blocklisted hosts and domains.

%s can generate output in multiple formats (default is text written to STDOUT).
Output selection is via the "-o" option; multiple uses of "-o" are honored. eg:

    -o text=block.text -o unbound=block.conf
    -o unbound=block.conf,text=block.text

'txt' can be used as a synonym for 'text' output format;
similarly, 'unb' can be used as a synonym for 'unbound' output format. These are
the only two output formats supported.

%s can optionally read a feed (txt file) of well known 3rd party malware and tracker URLs.
The feed.txt is a simple file:

- Each line starts with a URL containing blocklisted domains/hosts
- Optionally, the feed-type can be a second word "txt" or "json".
- The keyword 'txt' or 'json' identifies the type of output returned by the URL

Example:
	http://pgl.yoyo.org/files/adhosts/plaintext
	http://mirror2.malwaredomains.com/files/justdomains json

Options:
`, Z, Z)

		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	// validate all output formats
	for k, _ := range output {
		if _, ok := outfp[k]; !ok {
			die("unknown output format '%s'", k)
		}
	}

	bb := blgen.NewBuilder(cachedir, nocache, Progress)
	for _, f := range wl {
		Progress("Adding allowlist from %s ..", f)
		err := bb.AddAllowlist(f)
		if err != nil {
			die("%s", err)
		}
	}

	if len(feed) > 0 {
		Progress("Adding feed from %s ..", feed)
		err := addfeed(bb, feed)
		if err != nil {
			die("%s", err)
		}
	}

	// finally, add the various blocklist files from the command
	// line
	args := flag.Args()
	for _, f := range args {
		Progress("Adding blocklist from %s ..", f)
		err := bb.AddBlocklist(f)
		if err != nil {
			die("%s", err)
		}
	}

	bl, err := bb.Finalize()
	if len(err) != 0 {
		die("%v", err)
	}

	var wg sync.WaitGroup

	for typ, fn := range output {
		var fd io.Writer
		fp := outfp[typ]

		if len(fn) == 0 || fn == "-" {
			fd = os.Stdout
		} else {
			fx, err := newTempFile(fn)
			if err != nil {
				die("can't create %s: %s", fn, err)
			}

			fd = fx
		}

		wg.Add(1)
		go func(wg *sync.WaitGroup, fd io.Writer) {
			defer wg.Done()

			fp(bl, fd)

			if fx, ok := fd.(*tmpFile); ok {
				fx.Close()
			}
		}(&wg, fd)
	}

	if len(wlout) > 0 {
		fd, err := newTempFile(wlout)
		if err != nil {
			die("can't create %s: %s", wlout, err)
		}

		wg.Add(1)
		go func() {
			fmt.Fprintf(fd, "# Allowlist %d entries\n%s\n", len(bl.Allowlist),
				strings.Join(bl.Allowlist, "\n"))

			fd.Close()
			wg.Done()
		}()
	}

	wg.Wait()
}

// generate a simple text dump of domains and hosts
func textOut(b *blgen.BL, fd io.Writer) {
	fmt.Fprintf(fd, `# %d domains, %d hosts
# -- Domains --
%s
# -- Hosts --
%s
`, len(b.Domains), len(b.Hosts), strings.Join(b.Domains, "\n"), strings.Join(b.Hosts, "\n"))
}

func addfeed(bb *blgen.Builder, feed string) error {
	fd, err := os.Open(feed)
	if err != nil {
		return err
	}

	defer fd.Close()

	rd := bufio.NewScanner(fd)
	for rd.Scan() {
		s := strings.TrimSpace(rd.Text())
		if len(s) == 0 || s[0] == '#' {
			continue
		}

		var json bool = false
		v := strings.Fields(s)
		if len(v) > 1 {
			switch v[1] {
			case "", "txt", "text":
				json = false

			case "json", "JSON":
				json = true
			}
		}

		bb.AddBlocklistURL(v[0], json)

	}
	return nil
}

// implements io.WriteCloser
type tmpFile struct {
	*os.File
	orig string
	tmp  string
}

func newTempFile(fn string) (*tmpFile, error) {
	tmp := tmpName(fn)
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}

	return &tmpFile{
		File: fd,
		orig: fn,
		tmp:  tmp,
	}, nil
}

func (t *tmpFile) Close() error {
	err := t.File.Close()
	if err != nil {
		return err
	}

	return os.Rename(t.tmp, t.orig)
}

func (t *tmpFile) Abort() {
	t.File.Close()
	os.Remove(t.tmp)
}

func tmpName(fn string) string {
	var b [4]byte

	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		die("can't read random bytes: %s", err)
	}

	return fmt.Sprintf("%s-%d.%x", fn, os.Getpid(), b[:])
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
