#
# Generate adblock hosts for unbound
#


arch = $(shell ./build --print-arch)

bindir = ./bin/$(arch)
bin = $(bindir)/blgen

WL = $(wildcard allowlist.txt)
BL = $(wildcard blocklist.txt)

ifneq ($(WL),)
	input += -W $(WL)
endif

ifneq ($(BL),)
	input += $(BL)
endif

conf = big.conf

all: $(conf)

small.conf: smallfeed.txt $(WL) $(BL) $(bin) phony
	$(bin) -v -o $@ -f unbound -F $< $(input)

big.conf: bigfeed.txt $(WL) $(BL) $(bin) phony
	$(bin) -v --output-allowlist allowed.txt -f text -F $< $(input) | tee $(basename $@).txt | ./unbound.py > $@

bigfeed.txt: smallfeed.txt newfeed.txt
	cat $^ > $@

$(bin): ./blgen ./internal/blgen
	./build -s

.PHONY: phony
.SUFFIXES: .conf .txt

clean: phony
	-rm -f bad-* $(conf)

realclean: clean
	-rm -f .????*.txt .????*.json

phony:

