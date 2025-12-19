#!/bin/bash

# Build Release Script for Supply Tracer
# Builds binary for multiple platforms and creates release artifacts

set -e

VERSION="${1:-v1.0.0}"
BUILD_TIME=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS="-X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.Commit=$COMMIT"

RELEASE_DIR="releases/$VERSION"
mkdir -p "$RELEASE_DIR"

echo "🔨 Building Supply Tracer Release: $VERSION"
echo "   Commit: $COMMIT"
echo "   Build Time: $BUILD_TIME"
echo ""

# Platforms to build for
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for platform in "${PLATFORMS[@]}"; do
    OS=$(echo $platform | cut -d/ -f1)
    ARCH=$(echo $platform | cut -d/ -f2)
    OUTPUT="$RELEASE_DIR/tracer-$OS-$ARCH"
    
    if [ "$OS" = "windows" ]; then
        OUTPUT="$OUTPUT.exe"
    fi
    
    echo "📦 Building for $OS/$ARCH..."
    
    GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build \
        -ldflags "$LDFLAGS" \
        -o "$OUTPUT" \
        ./cmd/tracer
    
    # Create checksum
    if command -v sha256sum &> /dev/null; then
        sha256sum "$OUTPUT" > "$OUTPUT.sha256"
    elif command -v shasum &> /dev/null; then
        shasum -a 256 "$OUTPUT" > "$OUTPUT.sha256"
    fi
    
    echo "   ✓ Created: $(basename $OUTPUT)"
done

# Create tarball distributions
echo ""
echo "📦 Creating distribution packages..."

cd "$RELEASE_DIR"

# Linux distributions
for arch in amd64 arm64; do
    tar -czf "tracer-linux-$arch.tar.gz" "tracer-linux-$arch"
    echo "   ✓ tracer-linux-$arch.tar.gz"
done

# macOS distributions
for arch in amd64 arm64; do
    zip -q "tracer-darwin-$arch.zip" "tracer-darwin-$arch"
    echo "   ✓ tracer-darwin-$arch.zip"
done

# Windows distribution
zip -q "tracer-windows-amd64.zip" "tracer-windows-amd64.exe"
echo "   ✓ tracer-windows-amd64.zip"

cd - > /dev/null

# Create checksums file
echo ""
echo "📋 Creating checksums file..."
cd "$RELEASE_DIR"
ls *.sha256 2>/dev/null | xargs cat > CHECKSUMS
echo "   ✓ Created CHECKSUMS file"
cd - > /dev/null

# Create release notes
echo ""
echo "📝 Creating release notes..."
cat > "$RELEASE_DIR/RELEASE_NOTES.md" << EOF
# Supply Tracer Release $VERSION

**Build Information:**
- Version: $VERSION
- Build Time: $BUILD_TIME
- Commit: $COMMIT

## Artifacts

This release includes pre-compiled binaries for:

### Linux
- \`tracer-linux-amd64\` - Intel/AMD 64-bit
- \`tracer-linux-arm64\` - ARM 64-bit (Raspberry Pi 4, Apple Silicon with Docker)

### macOS
- \`tracer-darwin-amd64\` - Intel Macs
- \`tracer-darwin-arm64\` - Apple Silicon Macs

### Windows
- \`tracer-windows-amd64.exe\` - Windows 64-bit

## Installation

### Quick Install (Linux/macOS)
\`\`\`bash
curl -L https://github.com/Nash0810/TraceOrigin/releases/download/$VERSION/tracer-linux-amd64 \
  -o /usr/local/bin/tracer
chmod +x /usr/local/bin/tracer
\`\`\`

### Docker
\`\`\`bash
docker pull ghcr.io/Nash0810/traceorigin:$VERSION
docker run ghcr.io/Nash0810/traceorigin:$VERSION --help
\`\`\`

## Verification

All binaries are signed with checksums. Verify using:

\`\`\`bash
sha256sum -c CHECKSUMS
\`\`\`

## What's New in $VERSION

- ✨ New features
- 🐛 Bug fixes
- 📚 Documentation improvements
- ⚡ Performance enhancements

See CHANGELOG.md for details.

## Support

- 📖 [Documentation](https://github.com/Nash0810/TraceOrigin/wiki)
- 🐛 [Report Issues](https://github.com/Nash0810/TraceOrigin/issues)
- 💬 [Discussions](https://github.com/Nash0810/TraceOrigin/discussions)
EOF

echo "   ✓ Created RELEASE_NOTES.md"

echo ""
echo "✅ Release build complete!"
echo ""
echo "📊 Release contents:"
ls -lh "$RELEASE_DIR" | tail -n +2 | awk '{print "   " $9 " (" $5 ")"}'
echo ""
echo "📤 To publish this release:"
echo "   gh release create $VERSION -d -F $RELEASE_DIR/RELEASE_NOTES.md $RELEASE_DIR/*"
