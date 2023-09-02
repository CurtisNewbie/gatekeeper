FROM golang:1.18-alpine as build
LABEL author="Yongjie Zhuang"
LABEL descrption="Gatekeeper - Simple gateway written in Go"

RUN apk --no-cache add tzdata
WORKDIR /go/src/build/

# for golang env
RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct

# dependencies
COPY go.mod .
COPY go.sum .

RUN go mod download

# build executable
COPY . .
RUN go build -o main

FROM alpine:3.17
WORKDIR /usr/src/
COPY --from=build /go/src/build/main ./main
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
ENV TZ=Asia/Shanghai

CMD ["./main", "app.name=gatekeeper", "configFile=/usr/src/config/app-conf-prod.yml"]
