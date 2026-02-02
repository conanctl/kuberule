FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o kuberule-backend main.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/kuberule-backend /usr/local/bin/kuberule-backend
COPY --from=builder /app/guardrails/packs /app/guardrails/packs

ENV PORT=18081
ENV GUARDRAILS_DIR=/app/guardrails/packs
EXPOSE 18081

ENTRYPOINT ["kuberule-backend"]
