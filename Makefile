# Copyright (c) 2023 Volvo Car Corporation
# SPDX-License-Identifier: BSD-3-clause
VERSION := 0.1.0
SHA256SUM := 98210011d07d3ce56cba8d4550ceb423e2715a4b74e513f0e259a2496cf7f37b
ARCH := amd64

define docker_build
docker build --platform=$(ARCH) \
	--build-arg ARCH=$(ARCH) \
	--build-arg VERSION=$(VERSION) \
	--progress plain --target $(1) -t pkcs11gn-$(ARCH) .
endef

all: pkcs11gn

clean:
	rm pkcs11gn
	rm -rf *.deb

.PHONY: test
deb_test:
	$(call docker_build,test)

pkcs11gn_$(VERSION)-1_$(ARCH).deb: debian/* *.go go.* Dockerfile
	$(call docker_build,test)   # build & test & remove container
	$(call docker_build,deb)
	id=`docker create pkcs11gn-$(ARCH)` && docker cp "$$id:/build/$@" .
	test "$$(sha256sum <$@)" = '$(SHA256SUM)  -'

pkcs11gn_$(VERSION)-1_$(ARCH).deb.sig: pkcs11gn_$(VERSION)-1_$(ARCH).deb
	rm -f '$@'
	gpg --output '$@' --detach-sig '$<'

deb: pkcs11gn_$(VERSION)-1_$(ARCH).deb

sig: pkcs11gn_$(VERSION)-1_$(ARCH).deb.sig

pkcs11gn: main.go
	go build -o pkcs11gn -ldflags "-s -w"

.PHONY: test
test:
	go test -v ./...

.PHONY: coverage
coverage:
	go test ./... -coverprofile=cover.out
