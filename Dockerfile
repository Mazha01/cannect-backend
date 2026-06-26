# syntax=docker/dockerfile:1.7

FROM golang:1.25-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath -ldflags="-s -w" \
        -o /out/cannect ./cmd/cannect

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cannect /cannect
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/cannect"]
