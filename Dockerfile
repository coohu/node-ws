FROM golang:1.22 AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o app

FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/app /app/app

EXPOSE 3000
USER nonroot:nonroot

ENTRYPOINT ["/app/app"]
