# ==========================================
# Stage 1: Build Stage
# ==========================================
FROM golang:1.26.2-alpine3.23 AS builder

# Set the working directory inside the container
WORKDIR /app

# Install protoc dependencies
RUN apk add --no-cache protobuf-dev protoc git

WORKDIR /app

# Copy project files
COPY go.mod ./
COPY proto/ proto/
COPY cmd/ cmd/

# Install Protoc Go plugins
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate gRPC Protobuf Go code
RUN protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    proto/wirerelay/v1/wirerelay.proto

# Populate go.sum and resolve all gRPC dependency entries automatically
RUN go mod tidy

# Run unit & integration tests before compiling binaries
RUN go test -v ./...

# Compile statically linked Linux binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/wirerelay ./cmd/wirerelay
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/wirerelay-testbridge ./cmd/wirerelay-testbridge

# ==========================================
# Stage 2 - Target 1: WireRelay Core Image
# ==========================================
FROM alpine:latest AS wirerelay

RUN apk add --no-cache wireguard-tools iproute2 iptables ca-certificates

COPY --from=builder /bin/wirerelay /usr/local/bin/wirerelay
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080 9000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# ==========================================
# Stage 2 - Target 2: WireRelay Bridge Tester Image
# ==========================================
FROM alpine:latest AS wirerelay-testbridge

RUN apk add --no-cache ca-certificates

COPY --from=builder /bin/wirerelay-testbridge /usr/local/bin/wirerelay-testbridge

EXPOSE 8090

ENTRYPOINT ["/usr/local/bin/wirerelay-testbridge"]
