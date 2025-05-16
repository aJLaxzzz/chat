# Build stage
FROM golang:1.23 AS builder

WORKDIR /app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o chat-app .

# Runtime stage
FROM alpine:3.19

WORKDIR /app
COPY --from=builder /app/chat-app .
COPY --from=builder /app/templates ./templates

ENV DB_HOST=db
ENV DB_USER=admin
ENV DB_PASSWORD=admin
ENV DB_NAME=chatdb

EXPOSE 8080

CMD ["./chat-app"]
