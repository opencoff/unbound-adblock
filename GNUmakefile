#
# Generate adblock hosts for unbound
#
# mk-adblock.py: Parse various feeds in the internet and generate a
# 			   flat file containing bad domains and IPs
#
#
#

WL = $(wildcard whitelist.txt)
BL = $(wildcard blacklist.txt)

mkadblock = python ./mk-adblock.py

ifneq ($(WL),)
	wlopt = -w $(WL)
endif

ifneq ($(BL),)
	input += $(BL)
endif

ifeq ($(FLUSH),1)
	flush = -f
endif


bad = bad-hosts.txt
conf = $(bad:.txt=.conf)

.PHONY: phony
.SUFFIXES: .conf .txt

all: $(bad)


$(bad): bigfeed.txt $(WL) $(BL) phony
	$(mkadblock) --summary $(flush) $(wlopt) -u $(conf) -p bad- -L $< $(input)


clean: phony
	-rm -f bad-*

realclean: clean
	-rm -f .????*.txt .????*.json

phony:

