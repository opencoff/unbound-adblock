// main.go -- test program for dns blacklist host generator
//
// License GPLv2

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/opencoff/unbound-adblock/internal/blacklist"

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
	var format string
	var wl StringList
	var outfile string
	var cachedir string
	var nocache bool
	var wlout string

	flag.BoolVarP(&nocache, "no-cache", "", false, "Ignore the cached blocklist")
	flag.BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output")
	flag.StringVarP(&feed, "feed", "F", "", "Read blacklists from feed file `F`")
	flag.VarP(&wl, "whitelist", "W", "Add whistlist entries from file `F`")
	flag.StringVarP(&format, "output-format", "f", "", "Set output format to `T` (text or unbound)")
	flag.StringVarP(&outfile, "output-file", "o", "", "Write output to file `F`")
	flag.StringVarP(&cachedir, "cache-dir", "c", ".", "Use `D` as the cache directory")
	flag.StringVarP(&wlout, "output-whitelist", "", "", "Write whitelist output to `F`")

	flag.Usage = func() {
		fmt.Printf(`Usage: %s [options] [blacklist ...]

Read one or more blacklist files and generate a composite file containing
blacklisted hosts and domains. The final output is by default written to STDOUT.

%s can optionally read a feed (txt file) of well known 3rd party malware and tracker URLs.
The feed.txt is a simple file:

- Each line starts with a URL containing blacklisted domains/hosts
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

	var output func(b *blacklist.BL, fd io.WriteCloser)
	var outfd io.WriteCloser = os.Stdout

	switch format {
	case "", "text", "txt":
		output = textOut

	case "unbound":
		output = unboundOut

	default:
		die("Unknown output format %s", format)
	}

	if len(outfile) > 0 {
		fd, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			die("can't create %s: %s", outfile, err)
		}

		defer fd.Close()
		outfd = fd
	}

	args := flag.Args()

	bb := blacklist.NewBuilder(cachedir, nocache, Progress)
	if len(wl.V) > 0 {
		for _, f := range wl.V {
			Progress("Adding whitelist from %s ..", f)
			err := bb.AddWhitelist(f)
			if err != nil {
				die("%s", err)
			}
		}
	}

	if len(feed) > 0 {
		Progress("Adding feed from %s ..", feed)
		err := addfeed(bb, feed)
		if err != nil {
			die("%s", err)
		}
	}

	// finally, add the various blacklist files from the command
	// line
	for _, f := range args {
		Progress("Adding blacklist from %s ..", f)
		err := bb.AddBlacklist(f)
		if err != nil {
			die("%s", err)
		}
	}

	bl, err := bb.Finalize()
	if len(err) != 0 {
		die("%v", err)
	}

	output(bl, outfd)

	if len(wlout) > 0 {
		fd, err := os.OpenFile(wlout, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			die("can't create %s: %s", wlout, err)
		}
		fmt.Fprintf(fd, "# Whitelist %d entries\n%s\n", len(bl.Whitelist),
			strings.Join(bl.Whitelist, "\n"))

		fd.Close()
	}
}

// generate a simple text dump of domains and hosts
func textOut(b *blacklist.BL, fd io.WriteCloser) {
	fmt.Fprintf(fd, `# %d domains, %d hosts
# -- Domains --
%s
# -- Hosts --
%s
`, len(b.Domains), len(b.Hosts), strings.Join(b.Domains, "\n"), strings.Join(b.Hosts, "\n"))
}

func addfeed(bb *blacklist.Builder, feed string) error {
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

		bb.AddBlacklistURL(v[0], json)

	}
	return nil
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
