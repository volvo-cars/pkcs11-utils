FROM golang:1.21-bullseye as build

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN go build -o pkcs11gn -ldflags "-s -w"

FROM build as deb

# install deps for building deb packages
RUN apt-get update \
    && apt-get install -y --no-install-recommends gettext-base xz-utils \
    && rm -rf /var/lib/apt/lists/*

# copy debian control files to output/
COPY debian/*  debian/control/

ARG ARCH
ARG VERSION

# transform control.envsubst -> envsubst
# create the control.tar.xz blob in a reproducible manner (same mtime)
# https://wilmer.gaa.st/blog/archives/3-.deb-files-are-ar-archives,-but-....html#c521
RUN mkdir -p debian/data/usr/bin \
    && cp pkcs11gn debian/data/usr/bin/ \
    && envsubst <debian/control/control.envsubst >debian/control/control \
    && rm debian/control/control.envsubst \
    && tar -cJf debian/control.tar.xz --mtime=1970-01-01 --sort=name -C debian/control . \
    && tar -cJf debian/data.tar.xz --mtime=1970-01-01 --sort=name -C debian/data . \
    && echo "2.0" >debian/debian-binary \
    && ar rc pkcs11gn_${VERSION}-1_${ARCH}.deb debian/debian-binary debian/control.tar.xz debian/data.tar.xz

FROM build as test

# install the staticcheck and cover tools
RUN go install honnef.co/go/tools/cmd/staticcheck@2023.1.6
RUN go install golang.org/x/tools/cmd/cover@latest

COPY example/* ./example/

# run tests
RUN go test -coverprofile cover.out && \
    go tool cover -func=cover.out

# run static analysis
RUN staticcheck .
