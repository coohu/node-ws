FROM golang:1.22 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o app

FROM gcr.io/distroless/base-debian12

WORKDIR /app
COPY --from=builder /app/app /app/app
COPY index.html /app/index.html

USER nonroot:nonroot
EXPOSE 3000
ENTRYPOINT ["/app/app"]
