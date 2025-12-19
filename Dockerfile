# Multi-stage build for Supply Tracer
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    make \
    clang \
    llvm \
    linux-headers \
    libelf-dev \
    zlib-dev \
    pkg-config

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source
COPY . .

# Build the CLI binary
RUN CGO_ENABLED=1 GOOS=linux go build -o tracer ./cmd/tracer

# Final stage - runtime image
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    zlib1g \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 tracer

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/tracer /usr/local/bin/tracer

# Copy docs for reference
COPY --from=builder /build/docs ./docs
COPY --from=builder /build/README.md .

# Give executable permissions
RUN chmod +x /usr/local/bin/tracer

# Switch to app user
USER tracer

# Default command
ENTRYPOINT ["tracer"]
CMD ["--help"]

# Labels for container metadata
LABEL maintainer="TraceOrigin Contributors"
LABEL description="Container Supply Chain Security Tracer"
LABEL version="1.0.0"
