FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o /bin/tls-fingerprint-echo ./cmd/tls-fingerprint-echo

FROM alpine:3.19
COPY --from=builder /bin/tls-fingerprint-echo /usr/local/bin/
EXPOSE 8443
CMD ["tls-fingerprint-echo"]
