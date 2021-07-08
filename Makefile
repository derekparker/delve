.DEFAULT_GOAL=test

BPF_OBJ := pkg/proc/bpf/trace.o
BPF_SRC := $(shell find . -type f -name '*.bpf.*')

check-cert:
	@go run _scripts/make.go check-cert

build:
	@go run _scripts/make.go build

$(BPF_OBJ): $(BPF_SRC)
	clang \
		-I /usr/include \
		-I /usr/src/kernels/$(uname -r)/tools/lib \
		-I /usr/src/kernels/$(uname -r)/tools/bpf/resolve_btfids/libbpf \
		-g -O2 \
		-c \
		-target bpf \
		-o $(BPF_OBJ) \
		pkg/proc/bpf/trace.bpf.c

build-bpf: $(BPF_OBJ)
	@env CGO_CFLAGS="-I /home/deparker/Code/libbpf/src" CGO_LDFLAGS="/usr/lib64/libbpf.a" go run _scripts/make.go build

install:
	@go run _scripts/make.go install

uninstall:
	@go run _scripts/make.go uninstall

test: vet
	@go run _scripts/make.go test

vet:
	@go vet $$(go list ./... | grep -v native)

test-proc-run:
	@go run _scripts/make.go test -s proc -r $(RUN)

test-integration-run:
	@go run _scripts/make.go test -s service/test -r $(RUN)

vendor:
	@go run _scripts/make.go vendor

.PHONY: vendor test-integration-run test-proc-run test check-cert install build vet
