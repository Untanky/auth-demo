FROM golang:1.19-alpine AS build_base

# Set the Current Working Directory inside the container
WORKDIR /tmp/webauthn-demo

RUN apk add --no-cache git build-base

# We want to populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

# Build the Go app
RUN go build -o ./out/webauthn-demo .

# Start fresh from a smaller image
FROM alpine:3.9 

# Set the Current Working Directory inside the container
WORKDIR /app

ENV GIN_MODE=release

RUN apk add ca-certificates

COPY config.json /app/config.json
COPY --from=build_base /tmp/webauthn-demo/out/webauthn-demo /app/webauthn-demo


# This container exposes port 8080 to the outside world
EXPOSE 8080

# Run the binary program produced by `go install`
CMD ["/app/webauthn-demo"]
