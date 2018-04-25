FROM golang:alpine
LABEL description="Obtains Google Analytics RealTime API metrics, and presents them to prometheus for scraping."

ENV APP_PATH /go/src/app

RUN mkdir $APP_PATH

WORKDIR $APP_PATH

COPY . .

#Install Glide, Git and dependencies
RUN apk --update add git openssh && \
    apk add --update ca-certificates && \
    apk add --no-cache curl && \
    curl https://glide.sh/get | sh && \
    glide install && \
    rm -rf /var/lib/apt/lists/* && \
    rm /var/cache/apk/*

CMD CRED_FILE="/go/src/app/config/ga_creds.json" CONFIG_FILE="/go/src/app/config/conf.yaml" go run ganalytics.go
