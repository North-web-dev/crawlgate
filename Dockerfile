FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /crawlgate ./cmd/crawlgate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /crawlgate /crawlgate
EXPOSE 8080
ENTRYPOINT ["/crawlgate"]
CMD ["--addr", "0.0.0.0:8080", "--allow-public"]
