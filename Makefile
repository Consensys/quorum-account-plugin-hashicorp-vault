GIT_COMMIT := $(shell git rev-parse HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
GIT_REPO := $(shell git ls-remote --get-url)
EXECUTABLE := "quorum-plugin-hashicorp-account-store"
OUTPUT_DIR := "build"
VERSION := "1.0.0"
LD_FLAGS="-X main.GitCommit=${GIT_COMMIT} -X main.GitBranch=${GIT_BRANCH} -X main.GitRepo=${GIT_REPO} \
-X main.Executable=${EXECUTABLE} -X main.Version=${VERSION} -X main.OutputDir=${OUTPUT_DIR}"
XC_ARCH := amd64
XC_OS := linux darwin windows
TARGET_DIRS := $(addsuffix -$(XC_ARCH), $(XC_OS))

.PHONY: ${OUTPUT_DIR}

default: clean build zip
	@echo Done!
	@ls -lha ${OUTPUT_DIR}/*

build: tools
	@mkdir -p ${OUTPUT_DIR}
	@LD_FLAGS=${LD_FLAGS} go generate ./metadata
	@gox \
		-parallel=3 \
		-os="${XC_OS}" \
		-arch="${XC_ARCH}" \
		-ldflags="-s -w" \
		-output "${OUTPUT_DIR}/{{.OS}}-{{.Arch}}/${EXECUTABLE}" \
		.

zip: build $(TARGET_DIRS)

$(TARGET_DIRS):
	@zip -j -FS -q ${OUTPUT_DIR}/$@/${EXECUTABLE}-go-${VERSION}.zip ${OUTPUT_DIR}/*.json ${OUTPUT_DIR}/$@/*

tools:
ifeq (, $(shell which gox))
	@go get -u github.com/mitchellh/gox
endif

clean:
	@rm -rf ${OUTPUT_DIR}
