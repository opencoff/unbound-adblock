#! /usr/bin/env python

# Generate a list of bad hosts by parsing known ad-serv domains,
# malware hosts and trackers.
#
# (c) 2014 Sudhi Herle <sudhi-at-herle.net>
# GPLv2 (strictly v2)
#
# Usage: $0 --help
#

import os, sys, stat, time
from os.path import basename, exists
from datetime import datetime
from md5 import md5
import json, socket
import argparse
import re, requests

# Gah! Some pages use utf8 unicode encoding and requests need to be
# told. THis is a gross hack. But works for now!
reload(sys)
sys.setdefaultencoding('utf8')

# We reuse the cache if it is less than a day old
CACHEAGE = 86400


Z         = basename(sys.argv[0])
__doc__   = """%s scans the lists/URLs provided on the command line
for Ad serving hosts, domains, trackers etc. and generates two
output lists: 'badhosts.txt' and 'badip.txt'.

An optional whitelist file can provide domains that must NOT be
considered malware or ads.

""" % Z


# Bad entries in the various lists
Garbage = [ '0', '0.0.0.0', '127.0.0.1', '1fe8', '255.255.255.255',
            '::1', 'electro-cablaj.ro?.7055475',
          ]


def progress():
    global P
    P.tick()

def warn(fmt, *args):
    s = "%s: %s" % (Z, fmt)
    if args:                 s  = s % args
    if not s.endswith('\n'): s += '\n'

    sys.stderr.write(s)
    sys.stderr.flush()

def die(fmt, *args):
    warn(fmt, *args)
    sys.exit(1)


def main():
    global __doc__
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-w", "--whitelist", dest='wl', action="store",
                      default="", metavar="F",
                      help="Whitelist domains in file 'F' [%(default)s]")
    parser.add_argument("-p", "--output-prefix", dest='prefix', action="store",
                      default="bad", metavar="S",
                      help="Use 'S' as the output file prefix [%(default)s]")
    parser.add_argument("-f", "--flush-cache", dest="flush", action="store_true",
                      default=False,
                      help="Flush the cache before download [%(default)s]")
    parser.add_argument("-s", "--summary", dest="summary", action="store_true",
                      default=False,
                      help="Print domain summary in the end[%(default)s]")
    parser.add_argument("-u", "--unbound", dest="unbound", action="store", 
                        default="", metavar='F',
                        help="Generate an unbound.conf fragment and write to file 'F' [%(default)s]")

    parser.add_argument("files", nargs="*", help="[FILE..]", default=[])
    parser.add_argument("-L", "--list", dest="feed", action="store",
                default="", metavar='F',
                help="Read list of feeds from file 'F' [%(default)s]")

    args = parser.parse_args()
    wl   = scanwhitelist(args.wl)
    db   = blacklistDB(wl)

    if len(args.feed) > 0:
        feed = readfeed(args.feed)
        doscan(db, feed2fd(feed, args.flush))

    if args.prefix.endswith('-'):
        args.prefix = args.prefix[:-1]

    # Now scan any files on the command-line
    doscan(db, argv2fd(args.files))

    for g in Garbage:
        db.nuke(g)

    db.finalize()
    h = db.hosts()   # includes hosts
    d = db.domains() # only domains
    w = db.whitelisted()

    z = d + h

    writelist(z, args.prefix + '-hosts.txt')
    writelist(w, args.prefix + "-WL.txt")

    #template = """    local-zone: "%(domain)s" static"""
    if len(args.unbound) > 0:
        g    = ( "   local-zone: \"%s\" static" % x for x in z )
        data = "\n".join(g)
        fmt  = { 'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z"),
                 'data': data,
                 'prog': sys.argv[0],
                 'count': len(h),
                }
        writefile(args.unbound, Unbound_template % fmt)

    if args.summary:
        print "blacklist: %d hosts, %d domains; whitelist: %d hosts" % (len(h), len(d), len(w))


def xstat(nm):
    try:
        st = os.stat(nm)
        return st
    except:
        return None

def isolder_than(st, age):
    """Return True if the stat entry shows its older than 'age'.
    Also return True if the file doesn't exist or has zero size."""

    if st is None:      return True
    if st.st_size == 0: return True

    now = time.time()
    if (st.st_mtime + age) < now: return True
    #if st.st_size == 0: return True
    return False


def url2fname(url, typ):
    """Convert a URL to a name in a deterministic manner."""
    x = md5(url)
    y = x.hexdigest()
    return ".%s.%s" % (y, typ)

def xrm(fn):
    """Remove a file if it is exists"""
    if exists(fn): os.unlink(fn)

def make_empty(fn):
    """Create an empty file"""
    fd = open(fn, 'wb')
    fd.close()

def urlcache(uhash, url):
    """Fetch and store a local cache of 'url'"""
    tmpf  = uhash + '.tmp'
    fd    = open(tmpf, 'wb')
    try:
        r = requests.get(url, timeout=2.0)
        fd.write(r.text)
        fd.close()
        os.rename(tmpf, uhash)
    except Exception, ex:
        warn("can't fetch '%s': %s", url, str(ex))
        fd.close()
        xrm(tmpf)


class blacklistDB:
    Host_re = re.compile(r'\|\|([a-z][a-z0-9-_.]+\.([a-z]{2,6}))\^\s*')
    IP_re   = re.compile(r'\|\|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\^')

    def __init__(self, wl={}):
        self.h    = {}
        self.i    = {}
        self.doms = {}
        self.wlh  = {}
        self.blh   = {}

        self.addwhitelist(wl)


    def finalize(self):
        """Finalize making the various lists"""

        sys.stderr.write("     Generating final list ..\r")
        sys.stderr.flush()

        def prune(d):
            z = {}
            for n in d.keys():
                progress()
                if not self.in_whitelist(n):
                    z[n] = True

            return z

        bld = prune(self.doms)
        tmp = prune(self.h)
        blh = {}

        # now, remove entries that already have a top-level
        # blacklist in bld
        for n in tmp.keys():
            for p in domparts(n):
                if p in bld: break
            else:
                blh[n] = True

        self.bld = bld
        self.blh = blh

    def in_whitelist(self, nm):
        """Return true if 'nm' is in the whitelist.
        Here, we try all suffixes of 'nm'"""

        # fast path.
        if nm in self.wlh: return True

        # See if any part of the host is in the whitelist
        for d in domparts(nm):
            if d in self.wlh:
                self.wlh[nm] = True
                return True

        return False

    def hosts(self):
        """Return all the bad hosts we have collected.
        """
        #k = self.blh.keys() + self.bld.keys()
        k = self.blh.keys()
        k.sort(cmp=domain_cmp)

        #d = self.bld.keys()
        #d.sort(cmp=domain_cmp)

        # TODO
        # We should list domains separately. Here is why:
        #  - we may wish to blacklist an entire sub-domain
        #    e.g., *.ads.facebook.com
        #  - and we want the blacklist DB to know this is the case
        #    and search for it explicitly.
        #
        #  - For now, we will only blacklist top-level _domains_ and
        #    individual hosts.
        return k

    def domains(self):
        """Return blacklisted domains"""
        k = self.bld.keys()
        k.sort(cmp=domain_cmp)
        return k

    def whitelisted(self):
        """Return list of whitelisted domains."""

        # we only pick whitelisted top-level domains. Individual
        # hosts are not needed.
        k = self.wlh.keys()
        k.sort(cmp=domain_cmp)
        return k

    def addwhitelist(self, wlh):
        """Add hosts in wlh to our whitelist db"""

        self.wlh = wlh


    def ips(self):
        return self.i.keys()

    def add(self, nm):
        isdom = False
        nm = nm.strip()
        if nm.find('.') < 0: return
        if is_ip(nm):        return
        if nm.endswith('.'):   nm = nm[:-1]
        if nm.startswith('.'):
            nm = nm[1:]
            isdom = True

        dv = nm.split('.')
        if isdom or len(dv) == 2:    # top level domain blacklisted!
            self.doms[nm] = True
        else:
            self.h[nm]    = True

        progress()

    def scanfile(self, fd):
        """Scan a file, ignore comments and return a list of hosts"""

        n = 0
        for line in fd:
            line = line.strip()
            if len(line) == 0 or line.startswith('#'):
                continue

            # Both files above have the hostname in the second column
            v = line.split()
            k = ''
            if len(v) == 1:
                k = v[0].lower()
            else:
                a = v[0].lower()
                b = v[1].lower()

                if is_ip(a):
                    k = b
                else:
                    try:
                        x = int(a)
                        k = b
                    except:
                        k = a

            self.add(k)
            n += 1

        return n


    def scanjson(self, fd):
        """Scan a JSON tracker file from disconnect.me and return a dict
        of hosts"""

        j = json.load(fd)
        n = 0
        for d in j:
            nm = d[u'domain'].lower()
            self.add(nm)
            n += 1

        return n


    def scan_easylist(self, fd):
        """Scan an easy-list like object and extract domains and IPs."""
        global Host_re, IP_re

        hx = blacklistDB.Host_re
        ix = blacklistDB.IP_re
        n  = 0

        for l in fd:
            l = l.strip()
            m = hx.match(l)
            if m is not None:
                x = m.group(1).lower()
                self.add(x)
                n += 1
                continue

            m = ix.match(l)
            if m is not None:
                x = m.group(1)
                self.i[x] = True
                continue

        return n

    def nuke(self, e):
        if e in self.h:
            del self.h[e]



class urldata:
    """cache for URL content. Minimizes network I/O to once every
    hour."""


    def __init__(self, url, typ, flush=False):
        self.uhash = url2fname(url, typ)
        self.url   = url
        if flush: xrm(self.uhash)

        if not exists(self.uhash):
            make_empty(self.uhash)

        st = xstat(self.uhash)
        if flush or isolder_than(st, CACHEAGE):
            #print str(st)
            self.suff = ' +fetch'
            urlcache(self.uhash, url)
        else:
            self.suff = ' +cache'

        self.fd = open(self.uhash)

    def name(self):
        n = len(self.url)
        if n > 64: n = 64

        return self.url[:n] + self.suff

    def __iter__(self):
        return self

    def next(self):
        x = self.readline()
        if len(x) == 0: raise StopIteration
        return x

    __next__ = next

    def readline(self):
        return self.fd.readline()

    def read(self):
        return self.fd.read()

    def close(self):
        self.fd.close()



class progressticker:
        spin = [ '-', '-', '-', '-', '\\', '\\', '\\', '\\', '|', '|', '|', '|', '/', '/', '/', '/', ]

        def __init__(self):
            self.s = 0

        def tick(self):
            c = self.spin[self.s]
            self.s += 1
            if self.s == len(self.spin):
                self.s = 0

            msg = c + '\r'
            sys.stderr.write(msg)
            sys.stderr.flush()



def domparts(nm):
    """Return all domain suffixes of 'nm'"""

    v = [nm]
    for i, c in enumerate(nm):
        if c == '.': v.append(nm[i+1:])

    v = v[::-1]
    # Don't return the TLD
    return v[1:]

def is_ip(a):
    """Return true if 'a' is an IP address; False otherwise"""
    fam = (socket.AF_INET, socket.AF_INET6)
    for f in fam:
        try:
            a = socket.inet_pton(f, a)
            return True 
        except:
            pass

    return False


def argv2fd(argv):
    """Generator that yields open fd's from names in argv"""
    if len(argv) == 0:
        return

    for fn in argv:
        fd = open(fn, 'rb')
        yield fd, fn, fn
        fd.close()

def feed2fd(feed, flush=False):
    """Turn a feed dict into a generator that yields fd-like object
    and feed-type"""

    for typ, url in feed:
        fd = urldata(url, typ, flush)
        t  = '.' + typ
        yield fd, t, fd.name()
        fd.close()


def scanwhitelist(fn):
    """Scan a file, ignore comments and return a list of hosts"""

    if len(fn) == 0:
        return {}

    fd = open(fn, 'rb')
    wl = {}
    for line in fd:
        line = line.strip().lower()
        if len(line) == 0 or line.startswith('#'):
            continue

        if line.startswith('.'): line = line[1:]
        wl[line] = True

    fd.close()
    return wl



def readfeed(fname):
    """Read a feed and build a dict"""
    fd = open(fname, 'rb')
    d  = []
    for l in fd:
        l = l.strip()
        if len(l) == 0 or l.startswith('#'): continue
        v = l.split()
        typ = v[0]
        url = v[1]
        d.append((typ, url))

    fd.close()
    return d


def doscan(db, gen):
    """Update dict 'bad' by running generator 'gen'"""

    for fd, fn, url in gen:
        msg = "          %s.. \r" % url
        n   = 0
        sys.stderr.write(msg)
        sys.stderr.flush()
        if fn.endswith(".json"):
            n = db.scanjson(fd)
        elif fn.endswith(".easy"):
            n = db.scan_easylist(fd)
        else:
            n = db.scanfile(fd)

        x = '%d\n' % n
        sys.stderr.write(x)


def domain_cmp(a,b):
    """Compare two domains - group domains by suffixes"""

    progress()
    x = a.split('.')
    y = b.split('.')
    for a, b in zip(x[::-1], y[::-1]):
        if a == b:
            continue
        return -1 if a < b else +1
    return 0


def writefile(fn, s):
    """Write string 's' to file 'fn'"""
    try:
        fd = open(fn, 'wb')
    except Exception, ex:
        die("Can't create file '%s': %s", fn, str(ex))

    fd.write(s)
    fd.close()


def writelist(l, fn):
    """Write list 'l' to file 'fd' separated by \n"""

    writefile(fn, '\n'.join(l))


Unbound_template = """# Unbound config for active malware or ad domain hosts
#
#   Auto-generated by %(prog)s on %(date)s
#   Total bad domains: %(count)d
#
# -- Do not edit --
server:
%(data)s

# EOF
"""

P = progressticker()

main()

# EOF
