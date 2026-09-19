# Delegent — build and install the two binaries from this checkout.
#
#   make build              build gateway/delegent and protocol/delegent-proto (gitignored)
#   make install            build, then copy both into BINDIR (default /usr/local/bin)
#   make uninstall          remove them from BINDIR
#   make inspector          build inspector/mcp-inspector (the MCP inspector web app)
#   make install-inspector  build it, then copy it into BINDIR
#   make css                recompile the inspector's and the dashboard's Tailwind sheets (downloads the CLI once)
#   make init               go run 'delegent init' (first run: ~/.delegent, master key, config)
#   make dashboard          go run the terminal dashboard (delegent dashboard) from source
#   make serve              go run the gateway + web dashboard (http://127.0.0.1:8090/) from source
#   make test               vet + test every module, like CI
#   make clean              delete the local build artifacts
#
# Override the destination:   make install BINDIR=$$HOME/.local/bin
# Override the version stamp: make install VERSION=v9.9.9
# Pass extra flags to a run:  make serve ARGS="--addr 127.0.0.1:9000"
#
# The build runs inside the go.work workspace, so the gateway compiles against the sibling
# protocol/ directory rather than the tagged release pinned in gateway/go.mod. Build targets
# always invoke `go build` (Go's own cache makes a no-change rebuild near-instant) so the
# version stamp can never go stale. sudo is used only when BINDIR is not writable by the
# current user — the same policy as install.sh.

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

# Same stamp the release workflow uses: the gateway tag without its "gateway/" prefix
# (v0.3.5, or v0.3.5-2-gabc1234-dirty between tags); "dev" outside a git checkout.
VERSION ?= $(shell git describe --tags --match 'gateway/v*' --always --dirty 2>/dev/null | sed 's|^gateway/||')
ifeq ($(strip $(VERSION)),)
VERSION := dev
endif

GOFLAGS := -trimpath
LDFLAGS := -s -w -X main.version=$(VERSION)

GATEWAY_BIN   := gateway/delegent
PROTOCOL_BIN  := protocol/delegent-proto
INSPECTOR_BIN := inspector/mcp-inspector
BINS          := $(GATEWAY_BIN) $(PROTOCOL_BIN)

.PHONY: all build build-gateway build-protocol install uninstall inspector install-inspector init dashboard serve css test clean

# install-bins copies the given binaries into BINDIR, escalating only when it has to.
define install-bins
	@mkdir -p "$(BINDIR)" 2>/dev/null || true
	@if [ -w "$(BINDIR)" ]; then \
		install -m 0755 $(1) "$(BINDIR)/"; \
	else \
		echo "$(BINDIR) is not writable by $$(id -un); using sudo"; \
		sudo mkdir -p "$(BINDIR)" && sudo install -m 0755 $(1) "$(BINDIR)/"; \
	fi
	@echo "installed $(notdir $(1)) $(VERSION) to $(BINDIR)"
	@case ":$$PATH:" in \
		*":$(BINDIR):"*) ;; \
		*) echo "note: $(BINDIR) is not on your PATH";; \
	esac
endef

all: build

build: build-gateway build-protocol

build-gateway:
	cd gateway && go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o delegent ./cmd/delegent

build-protocol:
	cd protocol && go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o delegent-proto ./cmd/delegent-proto

install: build
	$(call install-bins,$(BINS))
	@first=$$(command -v delegent 2>/dev/null); \
	if [ -n "$$first" ] && [ "$$first" != "$(BINDIR)/delegent" ]; then \
		echo "warning: 'delegent' currently resolves to $$first, which shadows $(BINDIR)/delegent"; \
	fi

uninstall:
	@if [ ! -d "$(BINDIR)" ] || [ -w "$(BINDIR)" ]; then \
		rm -f "$(BINDIR)/delegent" "$(BINDIR)/delegent-proto"; \
	else \
		echo "$(BINDIR) is not writable by $$(id -un); using sudo"; \
		sudo rm -f "$(BINDIR)/delegent" "$(BINDIR)/delegent-proto"; \
	fi
	@echo "removed delegent and delegent-proto from $(BINDIR)"

inspector:
	cd inspector && go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o mcp-inspector .

install-inspector: inspector
	$(call install-bins,$(INSPECTOR_BIN))

# Run straight from source (no install). Templates and CSS are embedded at compile time, so
# a template or `make css` change shows up on the next run.
init:
	cd gateway && go run -ldflags "$(LDFLAGS)" ./cmd/delegent init $(ARGS)

dashboard:
	cd gateway && go run -ldflags "$(LDFLAGS)" ./cmd/delegent dashboard $(ARGS)

serve:
	cd gateway && go run -ldflags "$(LDFLAGS)" ./cmd/delegent serve $(ARGS)

# The standalone Tailwind CLI bundles the framework, so no package.json or node_modules is
# needed. It is downloaded once into inspector/.cache (gitignored) for this OS/arch.
TAILWIND     := inspector/.cache/tailwindcss
TAILWIND_URL := https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-$(shell uname -s | sed 's/Darwin/macos/;s/Linux/linux/')-$(shell uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/')

$(TAILWIND):
	@mkdir -p $(dir $@)
	curl -fsSL -o $@ $(TAILWIND_URL) && chmod +x $@

css: $(TAILWIND)
	cd inspector && ../$(TAILWIND) -i static/input.css -o static/app.css --minify
	cd gateway/cmd/delegent/web && ../../../../$(TAILWIND) -i static/input.css -o static/app.css --minify

test:
	cd protocol  && go vet ./... && go test ./...
	cd gateway   && go vet ./... && go test ./...
	cd inspector && go vet ./... && go test ./...

clean:
	rm -f $(BINS) $(INSPECTOR_BIN)
