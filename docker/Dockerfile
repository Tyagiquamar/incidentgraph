# IncidentGraph Go binaries are built from the repo root; services select the
# binary via `command`. Mock LLM provider by default: no paid APIs anywhere.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
COPY migrations migrations
COPY datasets datasets
RUN CGO_ENABLED=0 go build -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -o /out/worker ./cmd/worker \
 && CGO_ENABLED=0 go build -o /out/mcp-server ./cmd/mcp-server

FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
COPY --from=build /out/ /app/
WORKDIR /app
EXPOSE 8090 8091
# Default binary; services override with `command:` (args are NOT appended).
CMD ["/app/api"]
