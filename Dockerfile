FROM golang:1.19-alpine AS server_build

# Set the Current Working Directory inside the container
WORKDIR /tmp/webauthn-demo

RUN apk add --no-cache git build-base

# We want to populate the module cache based on the go.{mod,sum} files.
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

# Build the Go app
RUN go build -tags prod -o ./out/webauthn-demo .

FROM node:19 AS client_build

WORKDIR /app

COPY client/package.json .
COPY client/yarn.lock .
RUN yarn install
COPY client .
RUN yarn build

# Start fresh from a smaller image
FROM alpine:3.9 AS final

# Set the Current Working Directory inside the container
WORKDIR /app

ENV GIN_MODE=release

RUN apk add ca-certificates

COPY server/config.json /app/config.json
COPY --from=server_build /tmp/webauthn-demo/out/webauthn-demo /app/webauthn-demo
COPY --from=client_build /app/dist /app/client

# This container exposes port 8080 to the outside world
EXPOSE 8080

# Run the binary program produced by `go install`
CMD ["/app/webauthn-demo"]
