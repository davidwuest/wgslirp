# --- Build stage ---
FROM golang:1.23-alpine AS build
WORKDIR /src

# Speed up builds by caching deps (none yet, but keep pattern)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest
COPY . .

# Build static-ish binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o wgrouter ./cmd/wgrouter

# --- Runtime stage ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /src/wgrouter /usr/local/bin/wgrouter
# Default configuration can be overridden via env

EXPOSE 51820/udp

ENTRYPOINT ["/usr/local/bin/wgrouter"]
