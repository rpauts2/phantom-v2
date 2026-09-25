FROM golang:1.26-alpine AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN CGO_ENABLED=0 go build -o /phantom ./cmd/phantom

FROM alpine:3.20
RUN adduser -D phantom
USER phantom
COPY --from=build /phantom /usr/local/bin/phantom
EXPOSE 8443 8080
ENTRYPOINT ["phantom", "-config", "/opt/phantom/config.yaml", "-phishlets", "/opt/phantom/phishlets"]
