CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra

BINS    = extractor fileless_plain payload
CARRIER = carrier.png

.PHONY: all clean carrier host-test

all: $(BINS) $(CARRIER)

extractor: extractor.c
	$(CC) $(CFLAGS) $< -o $@

fileless_plain: fileless_plain.c
	$(CC) $(CFLAGS) $< -o $@

payload: payload.c
	$(CC) -Os -nostdlib -static -fno-stack-protector \
	      -Wl,--nmagic,--build-id=none $< -o $@
	strip $@

carrier: $(CARRIER)
$(CARRIER): build_carrier.py payload
	python3 build_carrier.py payload $(CARRIER)

host-test: extractor $(CARRIER)
	@rm -f /tmp/stego_marker
	./extractor $(CARRIER)
	@test -f /tmp/stego_marker && echo "[ok] payload ran filelessly, marker dropped" \
	                            || echo "[FAIL] no marker"

clean:
	rm -f $(BINS) $(CARRIER)
