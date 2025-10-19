#!/bin/bash

set -e

export PATH=$PATH:$(go env GOPATH)/bin

cd ./backend

echo "format check"
if [ -n "$(gofmt -l .)" ]; then
    gofmt -l .
    echo "failed"
    exit 1
fi
echo "success"

echo "go mod tidy"
go mod tidy
if [ -n "$(git status --porcelain go.mod go.sum 2>/dev/null)" ]; then
    git diff go.mod go.sum
    echo "failed"
    exit 1
fi
echo "success"

echo "dependencies"
go mod download
go mod verify
echo "success"

echo "go vet"
go vet ./...
echo "success"

echo "staticcheck"
if ! command -v staticcheck &> /dev/null; then
    go install honnef.co/go/tools/cmd/staticcheck@latest
fi
staticcheck ./...
echo "success"

echo "gosec"
if ! command -v gosec &> /dev/null; then
    go install github.com/securego/gosec/v2/cmd/gosec@latest
fi
gosec ./...
echo "success"

echo "golangci-lint"
if ! command -v golangci-lint &> /dev/null; then
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
fi
golangci-lint run --timeout=5m
echo "success"

echo "tests"
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
echo "success"

echo "build"
go build -v -o kuberule-backend .
echo "success"

echo "binary execution"
timeout 5s ./kuberule-backend || code=$?
if [ $code -ne 124 ] && [ $code -ne 0 ]; then
    echo "failed"
    exit 1
fi
echo "success"

echo "all checks passed"
