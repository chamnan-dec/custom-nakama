# Stage 1: Build Nakama binary
FROM golang:1.25.0-bookworm AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build Nakama binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o /nakama/custom-nakama .

# Stage 2: Run Nakama
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    postgresql-client \
    wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /nakama

# Copy binary from builder
COPY --from=builder /nakama/custom-nakama /nakama/custom-nakama

# Copy migration files
COPY --from=builder /app/migrate /nakama/migrate

# Copy nakama.yml config
COPY --from=builder /app/nakama.yml /nakama/nakama.yml

# Create data directory
RUN mkdir -p /nakama/data

# Create non-root user (OpenShift compatible)
RUN groupadd -r -g 1000 nakama && \
    useradd -r -u 1000 -g nakama -d /nakama -s /bin/bash nakama && \
    chown -R nakama:nakama /nakama

# Switch to non-root user
USER nakama

# Expose ports
EXPOSE 7349 7350

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:7350/ || exit 1

# Run Nakama server with nakama.yml config
ENTRYPOINT ["/nakama/custom-nakama", "--config", "/nakama/nakama.yml"]