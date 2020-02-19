// main.go -- test program for dns blacklist host generator
//
// License GPLv2

package main

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"bufio"
	"strings"

	"github.com/opencoff/unbound-adblock/internal/blacklist"

	flag "github.com/opencoff/pflag"
)

var Z string = path.Base(os.Args[0])
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

	flag.BoolVarP(&Verbose, "verbose", "v", false, "Show verbose output")
	flag.StringVarP(&feed, "feed", "F", "", "Read blacklists from feed file `F`")
	flag.VarP(&wl, "whitelist", "W", "Add whistlist entries from file `F`")
	flag.StringVarP(&format, "output-format", "f", "", "Set output format to `T` (text or unbound)")

	flag.Usage = func() {
		fmt.Printf(`Usage: %s [options] [blacklist ...]

Read one or more blacklist files and generate a composite file containing
blacklisted hosts and domains. The final output is written to STDOUT.

%s can optionally read a feed (txt file) of well known 3rd party malware and tracker URLs.
The feed.txt is a simple file:
- Each line starts with either a 'txt' or 'json' followed by a URL.
- The keyword 'txt' or 'json' identifies the type of output returned by the URL

Example:

txt http://pgl.yoyo.org/files/adhosts/plaintext
txt http://mirror2.malwaredomains.com/files/justdomains

Options:
`, Z)

		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()
	args := flag.Args()

	bb := blacklist.NewBuilder()
	if len(wl.V) > 0 {
		for _, f := range wl.V {
			err := bb.AddWhitelist(f)
			if err != nil {
				die("%s", err)
			}
		}
	}

	if len(feed) > 0 {
		err := addfeed(bb, feed)
		if err != nil {
			die("%s", err)
		}
	}

	// finally, add the various blacklist files from the command
	// line
	for _, f := range args {
		err := bb.AddBlacklist(f)
		if err != nil {
			die("%s", err)
		}
	}

	bl, err := bb.Finalize()
	if len(err) != 0 {
		die("%v", err)
	}

	bl.Dump(os.Stdout)
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

		v := strings.Fields(s)
		if len(v) != 2 {
			return fmt.Errorf("malformed feed line '%s ..'", s)
		}

		switch v[0] {
		case "txt", "text":
			bb.AddBlacklistURL(v[1], false)

		case "json", "JSON":
			bb.AddBlacklistURL(v[1], true)
		}
	}
	return nil
}

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
