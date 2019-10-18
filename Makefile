GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-plugin-hashicorp-account-store"
OUTPUT_DIR := "$(shell pwd)/build"
VERSION := "1.0.0"
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=${OUTPUT_DIR}"
XC_ARCH := amd64
# XC_OS := linux darwin windows # TODO(cjh) enable cross compilation builds using cgo
XC_OS := darwin
TARGET_DIRS := $(addsuffix -$(XC_ARCH), $(XC_OS))

.PHONY: ${OUTPUT_DIR}

# default: clean test build zip
default: clean build zip
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
	@mkdir -p ${OUTPUT_DIR}
	@echo Output to ${OUTPUT_DIR}
	@LD_FLAGS=${LD_FLAGS} go generate ./internal/metadata
	@gox \
		-parallel=3 \
		-os="${XC_OS}" \
		-arch="${XC_ARCH}" \
		-ldflags="-s -w" \
		-output "${OUTPUT_DIR}/{{.OS}}-{{.Arch}}/${EXECUTABLE}" \
		.

zip: build $(TARGET_DIRS)

$(TARGET_DIRS):
	@zip -j -FS -q ${OUTPUT_DIR}/$@/${EXECUTABLE}-${VERSION}.zip ${OUTPUT_DIR}/*.json ${OUTPUT_DIR}/$@/*

tools: goimports gox
	@go mod download

goimports:
ifeq (, $(shell which goimports))
	@go get -u golang.org/x/tools/cmd/goimports
endif

gox:
ifeq (, $(shell which gox))
	@go get -u github.com/mitchellh/gox
endif

clean:
	@rm -rf ${OUTPUT_DIR}
