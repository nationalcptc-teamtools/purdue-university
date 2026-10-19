FROM golang:1.26 AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /cork ./cmd/cork \
 && mkdir -p /data \
 && touch /data/.keep \
 && chown -R 65532:65532 /data

FROM scratch
COPY --from=builder /cork /cork
COPY --from=builder --chown=65532:65532 /data/.keep /data/.keep
USER 65532:65532
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/cork", "serve", "--data", "/data", "--listen", "0.0.0.0:8443"]
