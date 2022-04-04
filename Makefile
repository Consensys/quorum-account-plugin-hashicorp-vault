GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-account-plugin-hashicorp-vault"
PACKAGE ?= quorum-account-plugin-hashicorp-vault
OUTPUT_DIR := "$(shell pwd)/build"
VERSION := "0.2.0-alpha.1"
GEN_LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=${OUTPUT_DIR}"
BUILD_LD_FLAGS=-s -w $(extraldflags)
DOCKER_GEN_LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=/shared"
OS_ARCH := "$(shell go env GOOS)-$(shell go env GOARCH)"

.PHONY: ${OUTPUT_DIR}

default: clean test build zip
	@echo Done!
	@ls ${OUTPUT_DIR}/*

checkfmt: tools
	@GO_FMT_FILES="$$(goimports -l `find . -name '*.go' | grep -v vendor | grep -v proto`)"; \
	test -z "$${GO_FMT_FILES}" || ( echo "Please run 'make fixfmt' to format the following files: \n$${GO_FMT_FILES}"; exit 1 )

fixfmt: tools
	@goimports -w `find . -name '*.go' | grep -v vendor | grep -v proto`

test: tools
	GOFLAGS="-mod=readonly" go test ./...

dist-local: clean build zip
	@[ "${PLUGIN_DEST_PATH}" ] || ( echo "Please provide PLUGIN_DEST_PATH env variable" ; exit 1)
	@mkdir -p ${PLUGIN_DEST_PATH}
	@cp ${OUTPUT_DIR}/dist/${PACKAGE}-${VERSION}-${OS_ARCH}.zip ${PLUGIN_DEST_PATH}/${PACKAGE}-${VERSION}-${OS_ARCH}.zip

dist: clean build zip
	@echo Done!
	@cat ${OUTPUT_DIR}/plugin-meta.json
	@ls ${OUTPUT_DIR}/*

build: checkfmt
	@mkdir -p ${OUTPUT_DIR}/dist
	@echo Output to ${OUTPUT_DIR}/dist
	@CGO_ENABLED=0 GOFLAGS="-mod=readonly" go run -ldflags=${GEN_LD_FLAGS} ./internal/metadata/gen.go
	@GOFLAGS="-mod=readonly" go build \
		-ldflags='$(BUILD_LD_FLAGS)' \
		-o "${OUTPUT_DIR}/dist/${EXECUTABLE}" \
		.

zip: build
	@zip -j -FS -q ${OUTPUT_DIR}/dist/${PACKAGE}-${VERSION}-${OS_ARCH}.zip ${OUTPUT_DIR}/*.json ${OUTPUT_DIR}/dist/*
	@shasum -a 256 ${OUTPUT_DIR}/dist/${PACKAGE}-${VERSION}-${OS_ARCH}.zip | awk '{print $$1}' > ${OUTPUT_DIR}/dist/${EXECUTABLE}-${VERSION}-${OS_ARCH}-sha256.checksum

# use this to build an alpine linux dist - for locally running dev changes in the acceptance tests
build-alpine: checkfmt
	@mkdir -p ${OUTPUT_DIR}/linux
	@echo Output to ${OUTPUT_DIR}/linux

	@docker run -it \
		--mount type=bind,src=${OUTPUT_DIR},dst=/shared \
		--mount type=bind,src=$(shell pwd),dst=/quorum-account-plugin-hashicorp-vault \
		--mount type=bind,src=/Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go,dst=/Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go \
		--mount type=bind,src=/Users/chrishounsom/go/src/github.com/ethereum/go-ethereum/crypto/secp256k1,dst=/Users/chrishounsom/go/src/github.com/ethereum/go-ethereum/crypto/secp256k1 \
		-w /quorum-account-plugin-hashicorp-vault \
		golang:1.13.10-alpine3.11 /bin/sh ./alpine-build.sh

build-alpine-docker:
	go test ./...
	CGO_ENABLED=0 go run -ldflags=${DOCKER_GEN_LD_FLAGS} ./internal/metadata/gen.go
	go build \
		-ldflags='$(BUILD_LD_FLAGS)' \
		-o "/shared/linux/${EXECUTABLE}" \
		.
	zip -j -FS -q /shared/linux/${EXECUTABLE}-${VERSION}.zip /shared/*.json /shared/linux/*
	shasum -a 256 /shared/linux/${EXECUTABLE}-${VERSION}.zip | awk '{print $$1}' > /shared/linux/${EXECUTABLE}-${VERSION}.zip.sha256sum

tools: goimports

goimports:
ifeq (, $(shell which goimports))
	@GO111MODULE=off go get -u golang.org/x/tools/cmd/goimports
endif

clean:
	@rm -rf ${OUTPUT_DIR}
