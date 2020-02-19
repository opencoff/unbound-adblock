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

	"github.com/opencoff/go-options"
)

var Z string = path.Base(os.Args[0])
var Verbose bool = false
var Optdesc string = fmt.Sprintf(`
Usage: %s [options] blacklist [blacklist ...]

Read one or more blacklist files and generate a composite file containing
blacklisted hosts and domains. The final output is written to STDOUT.

%s can optionally read a feed (txt file) of well known 3rd party malware and tracker URLs.
The feed.txt is a simple file:
- Each line starts with either a 'txt' or 'json' followed by a URL.
- The keyword 'txt' or 'json' identifies the type of output returned by the URL

Example:

    txt http://pgl.yoyo.org/files/adhosts/plaintext
    txt http://mirror2.malwaredomains.com/files/justdomains

--
#          Options
help       -h,--help            Show this help message and exit
verbose    -v,--verbose         Show verbose progress messages [False]
feed=      -F=T,--feed=T        Read a URL list (feed) from file 'T'
whitelist= -W=F,--whitelist=F   Read additional whitelist entries from file 'F'
--
Note: You can use "whitelist" option multiple times and every use is concatenative.
--
*
--`, Z, Z, Z)

var Optspec = options.MustParse(Optdesc)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	opt, err := Optspec.Interpret(os.Args, []string{})
	if err != nil {
		die("%s", err)
	}
	if opt.GetBool("help") {
		Optspec.PrintUsageAndExit()
	}
	if len(opt.Args) < 1 {
		die("Too few arguments. Try '%s --help'", Z)
	}

	var prio L.Priority = L.LOG_INFO

	if opt.GetBool("verbose") {
		Verbose = true
		prio = L.LOG_DEBUG

	}

	bb := blacklist.NewBuilder()
	if v := opt.GetMulti("whitelist"); v != nil {
		for _, f := range v {
			err := bb.AddWhitelist(f)
			if err != nil {
				die("%s", err)
			}
		}
	}

	if f, ok := opt.Get("feed"); ok {
		err := addfeed(bb, f)
		if err != nil {
			die("%s", err)
		}
	}

	// finally, add the various blacklist files from the command
	// line
	for _, f := range opt.Args {
		err := bb.AddBlacklist(f)
		if err != nil {
			die("%s", err)
		}
	}

	bl := bb.Finalize()

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
