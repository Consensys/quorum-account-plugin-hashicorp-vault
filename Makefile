GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-account-plugin-hashicorp-vault"
OUTPUT_DIR := "$(shell pwd)/build"
VERSION := "1.0.0"
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=${OUTPUT_DIR}"
DOCKER_LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=/shared"

.PHONY: ${OUTPUT_DIR}

default: clean test build zip
	@echo Done!
	@ls ${OUTPUT_DIR}/*

checkfmt: tools
	@GO_FMT_FILES="$$(goimports -l `find . -name '*.go' | grep -v vendor | grep -v proto`)"; \
	[ "$${GO_FMT_FILES}" == "" ] || ( echo "Please run 'make fixfmt' to format the following files: \n$${GO_FMT_FILES}"; exit 1 )

fixfmt: tools
	@goimports -w `find . -name '*.go' | grep -v vendor | grep -v proto`

test: tools
	@go test ./...

dist:
	@[ "${PLUGIN_DEST_PATH}" ] || ( echo "Please provide PLUGIN_DEST_PATH env variable" ; exit 1)
	@mkdir -p ${PLUGIN_DEST_PATH}
	@cp ${OUTPUT_DIR}/$(shell go env GOOS)-$(shell go env GOARCH)/${EXECUTABLE}-${VERSION}.zip ${PLUGIN_DEST_PATH}/${EXECUTABLE}-${VERSION}.zip

build: checkfmt
	@mkdir -p ${OUTPUT_DIR}/local
	@echo Output to ${OUTPUT_DIR}/local
	@CGO_ENABLED=0 go run -ldflags=${LD_FLAGS} ./internal/metadata/gen.go
	@go build \
		-ldflags="-s -w" \
		-o "${OUTPUT_DIR}/local/${EXECUTABLE}" \
		.

zip: build
	@zip -j -FS -q ${OUTPUT_DIR}/local/${EXECUTABLE}-${VERSION}.zip ${OUTPUT_DIR}/*.json ${OUTPUT_DIR}/local/*
	@shasum -a 256 ${OUTPUT_DIR}/local/${EXECUTABLE}-${VERSION}.zip | awk '{print $$1}' > ${OUTPUT_DIR}/local/${EXECUTABLE}-${VERSION}.zip.sha256sum

build-linux: checkfmt
	@mkdir -p ${OUTPUT_DIR}/linux
	@echo Output to ${OUTPUT_DIR}/linux

	@docker run -it \
		--mount type=bind,src=${OUTPUT_DIR},dst=/shared \
		--mount type=bind,src=$(shell pwd),dst=/quorum-account-plugin-hashicorp-vault \
		--mount type=bind,src=/Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go,dst=/Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go \
		--mount type=bind,src=/Users/chrishounsom/go/src/github.com/ethereum/go-ethereum/crypto/secp256k1,dst=/Users/chrishounsom/go/src/github.com/ethereum/go-ethereum/crypto/secp256k1 \
		-w /quorum-account-plugin-hashicorp-vault \
		golang:1.13.12 make build-linux-docker

build-linux-docker:
	apt-get update
	apt-get -y install zip

	go test ./...
	CGO_ENABLED=0 go run -ldflags=${DOCKER_LD_FLAGS} ./internal/metadata/gen.go
	go build \
		-ldflags="-s -w" \
		-o "/shared/linux/${EXECUTABLE}" \
		.
	zip -j -FS -q /shared/linux/${EXECUTABLE}-${VERSION}.zip /shared/*.json /shared/linux/*
	shasum -a 256 /shared/linux/${EXECUTABLE}-${VERSION}.zip | awk '{print $$1}' > /shared/linux/${EXECUTABLE}-${VERSION}.zip.sha256sum

build-alpine: checkfmt
	@mkdir -p ${OUTPUT_DIR}/linux
	@echo Output to ${OUTPUT_DIR}/linux

	@docker run -it \
		--mount type=bind,src=${OUTPUT_DIR},dst=/shared \
		--mount type=bind,src=$(shell pwd),dst=/quorum-account-plugin-hashicorp-vault \
		--mount type=bind,src=/Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go,dst=/Users/chrishounsom/go/src/github.com/jpmorganchase/quorum-account-plugin-sdk-go \
		--mount type=bind,src=/Users/chrishounsom/go/src/github.com/ethereum/go-ethereum/crypto/secp256k1,dst=/Users/chrishounsom/go/src/github.com/ethereum/go-ethereum/crypto/secp256k1 \
		-w /quorum-account-plugin-hashicorp-vault \
		golang:1.13.10-alpine3.11 /bin/sh ./linux-build.sh

build-alpine-docker:
	go test ./...
	CGO_ENABLED=0 go run -ldflags=${DOCKER_LD_FLAGS} ./internal/metadata/gen.go
	go build \
		-ldflags="-s -w" \
		-o "/shared/linux/${EXECUTABLE}" \
		.
	zip -j -FS -q /shared/linux/${EXECUTABLE}-${VERSION}.zip /shared/*.json /shared/linux/*
	shasum -a 256 /shared/linux/${EXECUTABLE}-${VERSION}.zip | awk '{print $$1}' > /shared/linux/${EXECUTABLE}-${VERSION}.zip.sha256sum

tools: goimports
	@go mod download

goimports:
ifeq (, $(shell which goimports))
	@go get -u golang.org/x/tools/cmd/goimports
endif

clean:
	@rm -rf ${OUTPUT_DIR}
