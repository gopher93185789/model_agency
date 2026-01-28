# syntax=docker/dockerfile:1

################################################################################
# Build stage
################################################################################
ARG GO_VERSION=1.25.3
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build

# Install Node.js + npm (needed for Tailwind)
RUN apt-get update && apt-get install -y \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache Go dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source
COPY . .

# Build args
ARG TARGETARCH
ENV PATH="/go/bin:${PATH}"

# Build frontend + backend
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.npm \
    go install github.com/a-h/templ/cmd/templ@latest && \
    templ generate && \
    npm install tailwindcss @tailwindcss/cli && \
    mkdir -p public && \
    npx @tailwindcss/cli -i ./globals.css -o ./public/dist.css && \
    CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /bin/server .

################################################################################
# Runtime stage
################################################################################
FROM alpine:3.19 AS final

# Runtime deps
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Non-root user
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

USER appuser

# Copy binary
COPY --from=build /bin/server /bin/server

EXPOSE 42069

ENTRYPOINT ["/bin/server"]
