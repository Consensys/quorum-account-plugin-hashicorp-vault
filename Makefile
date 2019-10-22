GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-plugin-hashicorp-account-store"
OUTPUT_DIR := "$(shell pwd)/build"
VERSION := "1.0.0"
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=${OUTPUT_DIR}"
TARGET_DIR := target

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

# TODO enable cgo compatible cross-compilation builds (requires providing C toolchain when using gox)
# build: checkfmt
build:
	@mkdir -p ${OUTPUT_DIR}/${TARGET_DIR}
	@echo Output to ${OUTPUT_DIR}
	@LD_FLAGS=${LD_FLAGS} go generate ./internal/metadata
	@go build \
	    -ldflags="-s -w" \
	    -o "${OUTPUT_DIR}/${TARGET_DIR}/${EXECUTABLE}" \
	    .

zip: build $(TARGET_DIR)

$(TARGET_DIR):
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
