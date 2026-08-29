FROM golang:1.21-alpine AS builder
WORKDIR /app

# Copy only the Go module files first to leverage caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code and build the binary
COPY main.go .
RUN go build -o main .

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .
EXPOSE 8080
CMD ["./main"]
