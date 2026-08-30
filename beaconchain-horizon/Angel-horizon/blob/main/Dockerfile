# ============================================
# Stage 1: Build the Go binary
# ============================================
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the main binary (horizon angel core)
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
