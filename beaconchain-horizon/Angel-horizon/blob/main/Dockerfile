# ============================================
# Stage 1: Build the Go binary
# ============================================
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# ============ Fix for go.sum mismatch ============
# This command syncs go.sum with go.mod, removing outdated entries
# and adding missing ones without touching your source code
# ==================================================
RUN go mod tidy

# Copy the rest of the source code
COPY . .

# Build the main binary
RUN go build -o horizon ./main.go

# ============================================
# Stage 2: Create lightweight runtime image
# ============================================
FROM alpine:latest

# Install bash and postgres client for the wait script
RUN apk --no-cache add ca-certificates bash postgresql-client

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/horizon .

# Copy static data (if any, e.g., validators.json)
COPY --from=builder /app/internal/data ./internal/data 2>/dev/null || true

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose default port
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
