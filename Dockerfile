# Multi-stage build for Supply Tracer
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    clang \
    llvm \
    linux-headers \
    libelf \
    zlib-dev \
    pkgconfig

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source
COPY . .

# Build the CLI binary
RUN CGO_ENABLED=1 GOOS=linux go build -o supply-tracer ./cmd/tracer

# Final stage - runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libelf \
    zlib \
    curl \
    ca-certificates

# Copy binary from builder
COPY --from=builder /build/supply-tracer /usr/local/bin/supply-tracer

# Copy docs for reference
COPY --from=builder /build/docs ./docs
COPY --from=builder /build/README.md .

# Give executable permissions
RUN chmod +x /usr/local/bin/supply-tracer

# Set entrypoint and default command
ENTRYPOINT ["/usr/local/bin/supply-tracer"]
CMD ["--help"]

# Labels for container metadata
LABEL maintainer="TraceOrigin Contributors"
LABEL description="Container Supply Chain Security Tracer"
LABEL version="1.0.0"
