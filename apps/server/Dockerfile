# syntax=docker/dockerfile:1.7

FROM golang:1.25-alpine AS builder

WORKDIR /src

ARG TARGETOS=linux
ARG TARGETARCH

# Build deps (git for private/public modules if needed).
RUN apk add --no-cache git ca-certificates

# Copy module files first for better Docker layer caching.
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
	go mod download

# Copy the server source.
COPY cmd ./cmd
COPY internal ./internal

# Single binary used by both api and worker via runtime flags.
RUN --mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/api


FROM alpine:3.21 AS production

WORKDIR /

# CA certs for HTTPS calls and wget for compose healthcheck.
RUN apk add --no-cache ca-certificates wget && \
	addgroup -S app && adduser -S -G app app

COPY --from=builder /out/app /app

USER app

ENTRYPOINT ["/app"]
