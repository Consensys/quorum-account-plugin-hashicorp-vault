GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-account-plugin-hashicorp-vault"
PACKAGE ?= quorum-account-plugin-hashicorp-vault
OUTPUT_DIR := "$(shell pwd)/build"
VERSION := "0.2.0-SNAPSHOT"
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
	gotestsum

itest: clean tools build zip
	 gotestsum -- github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/test/integration -tags integration
	 gotestsum -- github.com/consensys/quorum-account-plugin-hashicorp-vault/internal/test/integration -tags clefintegration

build: checkfmt
	@mkdir -p ${OUTPUT_DIR}/dist
	@echo Output to ${OUTPUT_DIR}/dist
	@CGO_ENABLED=0 go run -ldflags=${GEN_LD_FLAGS} ./internal/metadata/gen.go
	go build \
		-ldflags='$(BUILD_LD_FLAGS)' \
		-o "${OUTPUT_DIR}/dist/${EXECUTABLE}" \
		.

zip: build
	@zip -j -FS -q ${OUTPUT_DIR}/dist/${PACKAGE}-${VERSION}-${OS_ARCH}.zip ${OUTPUT_DIR}/*.json ${OUTPUT_DIR}/dist/*
	@shasum -a 256 ${OUTPUT_DIR}/dist/${PACKAGE}-${VERSION}-${OS_ARCH}.zip | awk '{print $$1}' > ${OUTPUT_DIR}/dist/${EXECUTABLE}-${VERSION}-${OS_ARCH}-sha256.checksum

tools: goimports gotestsum

goimports:
	go mod download golang.org/x/tools
	go install golang.org/x/tools/cmd/goimports

gotestsum:
	go install gotest.tools/gotestsum
	which gotestsum; true
	@echo ${PATH}
	export PATH=${PATH}:$(go env GOPATH)/bin
	which gotestsum; true

clean:
	@rm -rf ${OUTPUT_DIR}
