// blacklist.go -- BL/WL domain DB abstraction
//
// (c) 2018 Sudhi Herle
//
// License: GPLv2

// Blacklist faciliates the construction of a domain blacklist/whitelist
// from one or more sources. Each source can be a public URL containing
// domain names or a local file. A meta-source called "feed" can contain
// a list of URLs; this is a convenience feature.
// Once constructed, the blacklist DB can be queried for determining if a
// given name is blacklisted or not.
package blacklist

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
)

// Abstraction for a blacklist DB builder
// Consulting the blacklist is a two-step affair:
//    1) Build the blacklist by feeding it various lists, feeds etc.
//    2) Create a fast, read-only lookup table and use it
type Builder struct {
	sync.Mutex

	b *db // blacklist
	w *db // whitelist

	verbose  func(s string, v ...interface{})
	cachedir string
	nocache  bool

	final bool

	errs []error
}

// Make a new blacklist DB
func NewBuilder(cachedir string, nocache bool, prog func(s string, v ...interface{})) *Builder {
	if len(cachedir) == 0 {
		cachedir = "."
	}

	d := &Builder{
		b:        newDB(),
		w:        newDB(),
		verbose:  prog,
		cachedir: cachedir,
		nocache:  nocache,
	}

	return d
}

// Add blacklist hosts from a URL
// If 'isJSON' is true, then the URL is assumed to return JSON body in a
// "standard" format; see feedparser.go:fetchURL() for details.
func (d *Builder) AddBlacklistURL(u string, isJSON bool) error {
	ch := make(chan string, 2)
	go d.fetchURL(u, ch, isJSON)
	d.b.addFromChan(ch)
	return nil
}

// Add hosts from a file 'fn' to blacklist
func (d *Builder) AddBlacklist(fn string) error {
	return d.addList(d.b, fn, "blacklist")
}

// Add hosts from a file 'fn' to whitelist
func (d *Builder) AddWhitelist(fn string) error {
	return d.addList(d.w, fn, "whitelist")
}

// Finalize making the DB -- gather all hosts in a single place
// Return a structure meant for fast lookups
func (d *Builder) Finalize() (*BL, []error) {
	d.b.syncWait()
	d.w.syncWait()

	d.Lock()
	defer d.Unlock()
	if len(d.errs) > 0 {
		return nil, d.errs
	}

	var dom *sync.Map = d.b.domains
	var hosts *sync.Map = d.b.hosts

	if !d.final {
		var wg sync.WaitGroup

		d.progress("Finalizing ..")

		// Remove items that are in the whitelist
		wg.Add(2)
		go func() {
			dom = d.w.prune(d.b.domains)
			wg.Done()
		}()

		go func() {
			hosts = d.w.prune(d.b.hosts)
			wg.Done()
		}()

		wg.Wait()

		// remove entries in hosts that already have a top level domain in 'dom'
		hosts.Range(func(k, v interface{}) bool {
			h := k.(string)
			t := domTree(h)
			for _, p := range t {
				if _, ok := dom.Load(p); ok {
					hosts.Delete(h)
					return true
				}
			}
			return true
		})
		d.b.domains = dom
		d.b.hosts = hosts
		d.final = true
	}

	gather := func(a []string, m *sync.Map) []string {
		m.Range(func(k, v interface{}) bool {
			a = append(a, k.(string))
			return true
		})

		return domSort(a)
	}

	var wg sync.WaitGroup

	dl := make([]string, 0, 16384)
	hl := make([]string, 0, 32768)
	w1 := make([]string, 0, 2048)
	w2 := make([]string, 0, 2048)

	wg.Add(4)
	go func() {
		hl = gather(hl, hosts)
		wg.Done()
	}()

	go func() {
		dl = gather(dl, dom)
		wg.Done()
	}()

	go func() {
		w1 = gather(w1, d.w.domains)
		wg.Done()
	}()

	go func() {
		w2 = gather(w2, d.w.hosts)
		wg.Done()
	}()

	wg.Wait()

	w1 = append(w1, w2...)
	d.progress("Total %d bad hosts; %d domains, %d hosts (%d whitelisted)\n",
		len(dl)+len(hl), len(dl), len(hl), len(w1))
	db := &BL{
		Hosts:     hl,
		Domains:   dl,
		Whitelist: w1,
	}
	return db, nil
}

func (d *Builder) progress(s string, v ...interface{}) {
	if d.verbose != nil {
		d.verbose(s, v...)
	}
}

// -- methods on 'BL' --

// Fast lookup table
type BL struct {
	Domains   []string
	Hosts     []string
	Whitelist []string
}

// -- methods on 'db' --

// Representation of a whitelist or a blacklist DB
type db struct {

	// Exact domain name matches
	hosts *sync.Map

	// full and sub-domain name matches - these names start with '.'
	domains *sync.Map

	wg sync.WaitGroup
}

func newDB() *db {
	return &db{
		hosts:   new(sync.Map),
		domains: new(sync.Map),
	}
}

// add a list from file 'fn' into database 'db'
func (b *Builder) addList(d *db, fn, ty string) error {
	fd, err := OpenFileRO(fn)
	if err != nil {
		return fmt.Errorf("can't add %s %s: %s", ty, fn, err)
	}

	//b.log.Debug("adding %s from %s ..", ty, fn)

	// genlines will close the file when it's done reading
	ch := genlines(fd)
	d.addFromChan(ch)
	return nil
}

// Read from Chan 'ch' and populate the DB
// Spawns a go-routine. Caller must call d.SyncWait() before
// they can use the DB for lookups
func (d *db) addFromChan(ch chan string) {
	d.wg.Add(1)

	go func(ch chan string, wg *sync.WaitGroup) {
		for s := range ch {
			s = strings.ToLower(s)
			if filter(s) {
				continue
			}

			// remove trailing dots
			if s[len(s)-1] == '.' {
				s = s[:len(s)-1]
			}

			tld, ok := isValidTld(s)
			if !ok {
				continue
			}

			if s[0] == '.' {
				p := s[1:]
				d.domains.Store(p, true)
			} else if tld {
				d.domains.Store(s, true)
			} else {
				d.hosts.Store(s, true)
			}
		}
		wg.Done()
	}(ch, &d.wg)
}

// Wait for any go routines that did I/O to complete
func (d *db) syncWait() {
	d.wg.Wait()
}

// Prune items in 'm' that belong to this list
func (d *db) prune(m *sync.Map) *sync.Map {
	x := new(sync.Map)
	m.Range(func(k, v interface{}) bool {
		s := k.(string)
		t := domTree(s)
		if !matchSuffix(d.domains, t) && !matchSuffix(d.hosts, t) {
			x.Store(s, true)
		}
		return true
	})
	return x
}

// match suffixes in 't' against entries in 'm'; return true if suffix matches, false otherwise
func matchSuffix(m *sync.Map, t []string) bool {
	for _, p := range t {
		if _, ok := m.Load(p); ok {
			return true
		}
	}
	return false
}

// Convert a domain name into an array of names - each successively shorter by
// one sub-component. e.g., given 'www.aaa.bbb.ccc.com', this function
// returns an array of strings:
//      0: www.aaa.bbb.ccc.com
//      1: aaa.bbb.ccc.com
//      2: bbb.ccc.com
//      3: ccc.com
func domTree(s string) []string {
	var v []string

	n := 0
	v = append(v, s)
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			t := s[i+1:]
			v = append(v, t)
			n += 1
		}
	}

	if n <= 1 {
		return []string{s}
	}

	// we reverse so the TLD is at the top
	v = reverse(v)
	return v[1:]
}

func isValidTld(s string) (tld bool, ok bool) {
	if len(s) >= 255 {
		return false, false
	}
	v := strings.Split(s, ".")
	for _, x := range v {
		if len(x) >= 63 {
			return false, false
		}
	}

	ok = true
	if len(v) == 1 {
		tld = true
	}
	return
}

// return true if this is a top level domain
func domIsTopLevel(s string) bool {
	n := 0
	for _, c := range s {
		if c == '.' {
			n += 1
			if n > 1 {
				return false
			}
		}
	}

	return n == 1
}

// Filter out improbable or bad entries in the domain lists
func filter(s string) bool {
	// if this is a valid IP, we ignore it.
	if ii := net.ParseIP(s); ii != nil {
		return true
	}

	// if there are no domain suffixes, we ignore it
	if strings.Index(s, ".") < 0 {
		return true
	}

	if !_RX.Match([]byte(s)) {
		return true
	}

	return false
}

// Read fd and return a chan which yields lines
// This implcitly creates a go-routine to read in the background
func genlines(fd io.ReadCloser) chan string {
	ch := make(chan string)

	go func(ch chan string, fd io.ReadCloser) {
		var s string
		rd := bufio.NewScanner(fd)
		for rd.Scan() {
			s = strings.TrimSpace(rd.Text())
			if len(s) == 0 || s[0] == '#' {
				continue
			}

			ch <- s

		}
		close(ch)
		fd.Close()
	}(ch, fd)

	return ch
}

var (
	_RX = regexp.MustCompile(`^(?i:\.?[a-z]+([a-z0-9-]*[a-z0-9]+)?(\.([a-z]+([a-z0-9-]*[a-z0-9]+)?)+)*)$`)
)

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
