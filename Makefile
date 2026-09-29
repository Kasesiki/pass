OBJS = $(shell find src -name '*.rs')

target/release/pass: $(OBJS)
	cargo build --release

install: target/release/pass
	cp target/release/pass /usr/bin/pass

clean:
	cargo clean
