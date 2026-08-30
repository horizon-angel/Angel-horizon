FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
RUN go mod tidy
COPY . .
RUN go build -o horizon ./main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates bash postgresql-client
WORKDIR /root/
COPY --from=builder /app/horizon .
COPY --from=builder /app/internal/data ./internal/data 2>/dev/null || true
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
