===============================================
Script to generate Ad-block domains for unbound
===============================================

Take a list of known malware and ad-serving domains and generate an
amalgamated configuration file **fragment** for unbound_. This fragment when
included in the main body of *unbound.conf*, will block these hosts and
domains serving malware and/or intrusive ads.

Usage
-----
You will need GNU Make (any recent version). Assuming it is available as
``gmake``, type::

    gmake

This will generate the following files:

- *bad-hosts.conf*: Config file fragment for unbound_.
- *bad-hosts.txt*: human readable list of malware & ad-serving hosts/domains.
- *bad-WL.txt*: Hosts/domains that are excluded due to being whitelisted.

Include the file *bad-hosts.conf* in your *unbound.conf* as follows::

    # include auto-generated ad-block/malware list
    include: /path/to/bad-hosts.conf

And reload unbound config to use the new blacklist.

Details
-------
The script *mk-adblock.py* generates the files above. It uses a list of 3rd
party URLs describing malware and ad-serving domains. The script coalesces
multiple such lists into a single list and generates a final *unbound.conf*
fragment.

When fetching the contents of 3rd party URLs, the script caches it in the
current directory. The cache files look like so::

    .494c3e7d1ac6c0b7763e54929e9da5cf.txt

Rerunning ``make`` within a day will reuse the cache files. The 24 hour cache
liveness period is hardcoded in the script. Whether or not the cache is
re-used is shown via the progress bar.

.. _unbound: https://unbound.net/


Guide to source code
====================
The main script is *mk-adblock.py*; it takes as input one or more
hosts/domains to be blacklisted. Optionally, it can also take a text file
containing URLs of blacklist hosts/domains; this mechanism is referred to in
the script as a "feed". Incidentally, the file *bigfeed.txt* is a collection
of known blacklist URLs.

For other options of *mk-adblock.py*, try ``mk-adblock.py --help``.

.. vim: ft=rst:sw=4:ts=4:expandtab:tw=78:
