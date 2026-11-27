BINARY := bin/ssl-center
IMAGE ?= saitomikuya/ssl-center:latest
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: web build test vet docker docker-buildx docker-push clean

web:
	cd web && npm ci && npm run type-check && npm run build

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/server

test:
	go test -count=1 -v -race ./...

vet:
	go vet ./...

docker:
	docker build -t $(IMAGE) .

docker-buildx:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) .

docker-push:
	docker buildx build --platform $(PLATFORMS) -t $(IMAGE) --push .

clean:
	rm -rf bin/
