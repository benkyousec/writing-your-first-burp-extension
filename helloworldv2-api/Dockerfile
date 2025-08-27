FROM golang:1.24.6-alpine

RUN apk add --no-cache build-base sqlite bash

WORKDIR /app

COPY main.go go.mod go.sum init_db.sh ./

RUN go mod tidy

RUN go build -o app main.go

RUN chmod +x init_db.sh

RUN ./init_db.sh

EXPOSE 1337

CMD ["./app"]