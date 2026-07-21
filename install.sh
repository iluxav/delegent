#!/bin/sh
# Delegent installer — downloads the latest release binaries (delegent + delegent-proto)
# for this OS/arch from GitHub releases, verifies the sha256 checksum, and installs them.
#
#   curl -fsSL https://delegent.dev/install.sh | sh
#
# Options (env vars):
#   DELEGENT_INSTALL_DIR   install directory (default /usr/local/bin; falls back to
#                          ~/.local/bin when /usr/local/bin is not writable and sudo is absent)
#   DELEGENT_VERSION       install a specific version, e.g. v0.1.2 (default: latest release)
set -eu

REPO="iluxav/delegent"

err() { printf 'delegent install: %s\n' "$*" >&2; exit 1; }

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  darwin|linux) ;;
  *) err "unsupported OS: $OS (darwin and linux binaries are published; try: go install delegent.dev/gateway/cmd/delegent@latest)" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) err "unsupported architecture: $ARCH" ;;
esac

if [ -n "${DELEGENT_VERSION:-}" ]; then
  VERSION="$DELEGENT_VERSION"
else
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d'"' -f4) || true
  [ -n "${TAG:-}" ] || err "could not determine the latest release (GitHub API unreachable?)"
  VERSION="${TAG#gateway/}"
fi

# release tags contain a slash (gateway/vX.Y.Z) — URL-encode it for the download path
ENC_TAG="gateway%2F${VERSION}"
ASSET="delegent_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE="https://github.com/$REPO/releases/download/$ENC_TAG"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf 'downloading %s %s (%s_%s)...\n' "$REPO" "$VERSION" "$OS" "$ARCH"
curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET" || err "download failed: $BASE/$ASSET"
curl -fsSL "$BASE/checksums.txt" -o "$TMP/checksums.txt" || err "checksums download failed"

WANT=$(grep " $ASSET\$\|	$ASSET\$\|/$ASSET\$\| \./$ASSET\$" "$TMP/checksums.txt" | awk '{print $1}' | head -1)
[ -n "$WANT" ] || err "no checksum for $ASSET in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  GOT=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
else
  GOT=$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')
fi
[ "$WANT" = "$GOT" ] || err "checksum mismatch for $ASSET (want $WANT, got $GOT)"

tar -xzf "$TMP/$ASSET" -C "$TMP"

DIR="${DELEGENT_INSTALL_DIR:-/usr/local/bin}"
SUDO=""
if [ ! -w "$DIR" ] 2>/dev/null || [ ! -d "$DIR" ]; then
  if [ -z "${DELEGENT_INSTALL_DIR:-}" ] && command -v sudo >/dev/null 2>&1 && [ -t 0 ]; then
    SUDO="sudo"
  elif [ -z "${DELEGENT_INSTALL_DIR:-}" ]; then
    DIR="$HOME/.local/bin"
  fi
fi
$SUDO mkdir -p "$DIR"
$SUDO install -m 0755 "$TMP/delegent" "$TMP/delegent-proto" "$DIR/"

printf 'installed delegent and delegent-proto %s to %s\n' "$VERSION" "$DIR"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *) printf 'note: %s is not on your PATH\n' "$DIR" ;;
esac
printf 'get started:  delegent init\n'
