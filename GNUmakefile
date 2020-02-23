#
# Generate adblock hosts for unbound
#
# mk-adblock.py: Parse various feeds in the internet and generate a
# 			   flat file containing bad domains and IPs
#
#
#

os := $(shell uname | tr '[A-Z]' '[a-z]')
arch := $(shell uname -m)

x86_64-alias := amd64

ifneq ($($(arch)-alias),)
	arch := $($(arch)-alias)
endif

bindir = ./bin/$(os)-$(arch)
bin = $(bindir)/blgen

WL = $(wildcard whitelist.txt)
BL = $(wildcard blacklist.txt)

ifneq ($(WL),)
	wlopt = -W $(WL)
endif

ifneq ($(BL),)
	input += $(BL)
endif

conf = bad-hosts.conf big.conf

all: $(conf)

bad-hosts.conf: myfeed.txt $(WL) $(BL) $(bin)
	$(bin) -v -o $@ -f unbound -F $< $(wlopt) $(BL)

newbl.conf: newfeed.txt $(WL) $(BL) $(bin)
	$(bin) -v -o $@ -f unbound -F $< -W $(WL) -W whitelist.list $(BL)

big.conf: bigfeed.txt $(WL) whitelist.list $(BL) $(bin)
	$(bin) -v -o $@ --output-whitelist w.txt -f unbound -F $< -W $(WL) -W whitelist.list $(BL)

bigfeed.txt: myfeed.txt newfeed.txt
	cat $^ > $@

$(bin)::
	./build -s

.PHONY: phony $(bin)
.SUFFIXES: .conf .txt

clean: phony
	-rm -f bad-*

realclean: clean
	-rm -f .????*.txt .????*.json

phony:

