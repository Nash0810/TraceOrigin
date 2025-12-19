#!/bin/bash

# Installation Script for Supply Tracer
# One-line install: curl -sSL https://raw.githubusercontent.com/Nash0810/TraceOrigin/main/scripts/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VERSION="${TRACER_VERSION:-latest}"
INSTALL_DIR="${TRACER_INSTALL_DIR:-/usr/local/bin}"
REPO="Nash0810/TraceOrigin"

echo -e "${BLUE}🔧 Supply Tracer Installation Script${NC}"
echo ""

# Detect OS and architecture
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
    Linux)
        OS_NAME="linux"
        ;;
    Darwin)
        OS_NAME="darwin"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        OS_NAME="windows"
        ;;
    *)
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_NAME="amd64"
        ;;
    aarch64|arm64)
        ARCH_NAME="arm64"
        ;;
    armv7l)
        ARCH_NAME="armv7"
        ;;
    *)
        echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}📋 System Information:${NC}"
echo "  OS: $OS_NAME"
echo "  Architecture: $ARCH_NAME"
echo "  Version: $VERSION"
echo ""

# Determine download URL
if [ "$VERSION" = "latest" ]; then
    echo -e "${BLUE}🔍 Fetching latest release...${NC}"
    RELEASE_INFO=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest")
    VERSION=$(echo "$RELEASE_INFO" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": "\(.*\)".*/\1/')
else
    RELEASE_INFO=$(curl -sSL "https://api.github.com/repos/$REPO/releases/tags/$VERSION")
fi

if [ -z "$VERSION" ]; then
    echo -e "${RED}❌ Failed to fetch release information${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Latest version: $VERSION${NC}"
echo ""

# Construct download URL
if [ "$OS_NAME" = "windows" ]; then
    FILENAME="tracer-$OS_NAME-$ARCH_NAME.exe"
else
    FILENAME="tracer-$OS_NAME-$ARCH_NAME"
fi

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME"

# Check if binary exists
echo -e "${BLUE}📦 Downloading $FILENAME...${NC}"

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

BINARY_PATH="$TEMP_DIR/$FILENAME"

if ! curl -sSL -f -o "$BINARY_PATH" "$DOWNLOAD_URL"; then
    echo -e "${RED}❌ Failed to download Supply Tracer${NC}"
    echo "  URL: $DOWNLOAD_URL"
    exit 1
fi

echo -e "${GREEN}✓ Downloaded successfully${NC}"
echo ""

# Verify checksum if available
echo -e "${BLUE}🔐 Verifying checksum...${NC}"

CHECKSUM_URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME.sha256"
if curl -sSL -f -o "$TEMP_DIR/checksum" "$CHECKSUM_URL" 2>/dev/null; then
    cd "$TEMP_DIR"
    if sha256sum -c checksum 2>/dev/null; then
        echo -e "${GREEN}✓ Checksum verified${NC}"
    else
        echo -e "${YELLOW}⚠ Checksum verification failed (continuing anyway)${NC}"
    fi
    cd - > /dev/null
else
    echo -e "${YELLOW}⚠ Checksum file not available (skipping verification)${NC}"
fi

echo ""

# Make binary executable
chmod +x "$BINARY_PATH"

# Install binary
echo -e "${BLUE}📥 Installing to $INSTALL_DIR...${NC}"

if [ ! -w "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}⚠ $INSTALL_DIR is not writable, using sudo${NC}"
    sudo cp "$BINARY_PATH" "$INSTALL_DIR/tracer"
    sudo chmod +x "$INSTALL_DIR/tracer"
else
    cp "$BINARY_PATH" "$INSTALL_DIR/tracer"
fi

# Verify installation
if command -v tracer &> /dev/null; then
    INSTALLED_VERSION=$(tracer --version 2>/dev/null || echo "version unknown")
    echo -e "${GREEN}✓ Installation successful!${NC}"
    echo ""
    echo -e "${BLUE}📊 Installed:${NC}"
    echo "  Binary: $(which tracer)"
    echo "  Version: $INSTALLED_VERSION"
else
    echo -e "${RED}❌ Installation verification failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}🚀 Getting Started:${NC}"
echo "  tracer --help              # Show help"
echo "  tracer trace               # Start tracing"
echo "  tracer analyze <m> <t>     # Analyze manifest vs trace"
echo "  tracer sbom <t> <m>        # Generate SBOM"
echo ""

echo -e "${BLUE}📚 Documentation:${NC}"
echo "  https://github.com/$REPO"
echo ""

echo -e "${GREEN}✅ Installation complete!${NC}"
