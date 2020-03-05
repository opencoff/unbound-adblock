#
# Generate adblock hosts for unbound
#
# mk-adblock.py: Parse various feeds in the internet and generate a
# 			   flat file containing bad domains and IPs
#
#
#


arch = $(shell ./build --print-arch)

bindir = ./bin/$(arch)
bin = $(bindir)/blgen

WL = $(wildcard whitelist.txt)
BL = $(wildcard blacklist.txt)

ifneq ($(WL),)
	wlopt = -W $(WL)
endif

ifneq ($(BL),)
	input += $(BL)
endif

conf = big.conf

all: $(conf)

bad-hosts.conf: myfeed.txt $(WL) $(BL) $(bin)
	$(bin) -v -o $@ -f unbound -F $< $(wlopt) $(BL)

big.conf: bigfeed.txt $(WL) whitelist.list $(BL) $(bin)
	$(bin) -v -o $@ --output-whitelist w.txt -f unbound -F $< -W $(WL) -W whitelist.list $(BL)

bigfeed.txt: myfeed.txt newfeed.txt
	cat $^ > $@

$(bin): ./blgen ./internal/blacklist
	./build -s

.PHONY: phony
.SUFFIXES: .conf .txt

clean: phony
	-rm -f bad-*

realclean: clean
	-rm -f .????*.txt .????*.json

phony:

