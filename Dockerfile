FROM cgr.dev/chainguard/go:latest AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /open-pki ./cmd/open-pki/

FROM cgr.dev/chainguard/wolfi-base:latest
RUN mkdir -p /data && chown nonroot:nonroot /data
COPY --from=build /open-pki /usr/local/bin/open-pki
USER nonroot

EXPOSE 8300
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8300/v1/health || exit 1

ENTRYPOINT ["open-pki"]
CMD ["serve", "--db", "/data/open-pki.db"]
