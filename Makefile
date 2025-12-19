.PHONY: all
all: lint test

.PHONY: lint
lint:
	@echo "@==> $@"
	golangci-lint run --fix ./...

.PHONY: test
test:
	@echo "@==> $@"
	go test ./...

.PHONY: cover
cover:
	@echo "@==> $@"
	go test -race -covermode atomic -coverprofile=coverage.txt ./...
