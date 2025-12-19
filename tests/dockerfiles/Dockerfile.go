# Test Dockerfile for Go application with Supply Tracer

FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install Supply Tracer
RUN apk add --no-cache curl bash
RUN curl -sSL https://raw.githubusercontent.com/Nash0810/TraceOrigin/main/scripts/install.sh | bash

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Trace dependency downloads
RUN tracer trace --output /build/trace.json --format json || true

# Download dependencies (traced)
RUN go mod download

# Generate SBOM for Go dependencies
RUN tracer sbom /build/trace.json go.mod \
    --format=cyclonedx \
    --output=/build/sbom.json || true

# Validate SBOM
RUN tracer validate /build/sbom.json --db=osv || true

# Copy source
COPY . .

# Build application
RUN CGO_ENABLED=0 GOOS=linux go build -o /build/app .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Copy built binary
COPY --from=builder /build/app /app/app
COPY --from=builder /build/sbom.json /app/sbom.json

# Labels for testing
LABEL test="true"
LABEL tracer.scanned="true"
LABEL language="go"

# Run application
ENTRYPOINT ["/app/app"]
