# --- Build stage ---
FROM golang:1.23-alpine AS build
WORKDIR /src

# Speed up builds by caching deps (none yet, but keep pattern)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest
COPY . .

# Build static-ish binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o wgslirp ./cmd/wgslirp

# --- Runtime stage ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates

# Create a non-root user and group
RUN addgroup -S wgslirp && adduser -S -G wgslirp wgslirp

WORKDIR /app
COPY --from=build /src/wgslirp /usr/local/bin/wgslirp
# Default configuration can be overridden via env

# Ensure proper permissions
RUN chown -R wgslirp:wgslirp /app

EXPOSE 51820/udp
EXPOSE 8080/tcp

# Switch to non-root user
USER wgslirp

ENTRYPOINT ["/usr/local/bin/wgslirp"]
