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

	errs []error
}

// Make a new blacklist DB
func NewBuilder() *Builder {
	d := &Builder{
		b: newDB(),
		w: newDB(),
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

	// Remove items that are in the whitelist
	dom := d.w.prune(d.b.domains)
	hosts := d.w.prune(d.b.hosts)

	// remove entries in hosts that already have a top level domain in 'dom'
	hosts.Range(func (k, v interface{}) bool {
		h := k.(string)
		t := domTree(h)
		for _, p := range t {
			if _, ok := dom.Load(p); ok {
				hosts.Delete(k)
				return true
			}
		}
		return true
	})

	db := &BL{
		hosts:   hosts,
		domains: dom,
	}
	return db, nil
}

// -- methods on 'BL' --

// Fast lookup table
type BL struct {
	domains *sync.Map
	hosts   *sync.Map
}

// XXX golang says concurrent reads from a map are safe.
// Return true if 'nm' is blacklisted
func (b *BL) IsBlacklisted(nm string) bool {

	t := domTree(nm)

	return matchSuffix(b.domains, t) || matchSuffix(b.hosts, t)
}

func matchSuffix(m *sync.Map, t []string) bool {
	for _, p := range t {
		if _, ok := m.Load(p); ok {
			return true
		}
	}
	return false
}


// Write DB to file 'fd' and close
func (b *BL) Dump(w io.Writer) {

	gather := func(a []string, m *sync.Map) []string {
		m.Range(func(k, v interface{}) bool {
			a = append(a, k.(string))
			return true
		})

		return domSort(a)
	}

	var wg sync.WaitGroup

	dl := make([]string, 0, 1024)
	hl := make([]string, 0, 1024)

	wg.Add(1)
	go func() {
		hl = gather(hl, b.hosts)
		wg.Done()
	}()

	dl = gather(dl, b.domains)
	wg.Wait()

	fmt.Fprintf(w, "# %d domains, %d hosts\n# -- domains --\n%s\n# -- hosts --\n%s\n",
		len(dl), len(hl), strings.Join(dl, "\n"), strings.Join(hl, "\n"))
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
			if filter(s) {
				continue
			}

			// remove trailing dots
			if s[len(s)-1] == '.' {
				s = s[:len(s)-1]
			}

			if s[0] == '.' {
				p := s[1:]
				d.domains.Store(p, true)
			} else if domIsTopLevel(s) {
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
	m.Range(func (k, v interface{}) bool {
		s := k.(string)
		if !d.match(s) {
			x.Store(s, true)
		}
		return true
	})
	return x
}

// Return true if domain 'nm' is in the DB 'd'; false otherwise.
func (d *db) match(nm string) bool {

	t := domTree(nm)
	return matchSuffix(d.domains, t) || matchSuffix(d.hosts, t)
}


// Convert a domain name into an array of names - each successively shorter by
// one sub-component. e.g., given 'www.aaa.bbb.ccc.com', this function
// returns an array of strings:
//      0: www.aaa.bbb.ccc.com
//      1: aaa.bbb.ccc.com
//      2: bbb.ccc.com
//      3: ccc.com
func domTreeX(s string) []string {
	n := 0
	for _, c := range s {
		if c == '.' {
			n += 1
		}
	}

	if n <= 1 {
		return []string{s}
	}

	var v []string

	i := 0
	v = append(v, s)
	for i = 0; i < len(s); i++ {
		if s[i] == '.' {
			t := s[i+1:]
			v = append(v, t)
		}
	}

	// We don't want the TLD.
	v = reverse(v)
	return v[1:]
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

// vim: ft=go:sw=8:ts=8:noexpandtab:tw=98:
