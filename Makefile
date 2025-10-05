APP_NAME = user-service
BUILD_DIR = bin
BINARY_NAME = $(BUILD_DIR)/$(APP_NAME)

.PHONY: build run clean test docker-build docker-up docker-down

build:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BINARY_NAME) ./cmd/server

run:
	go run ./cmd/server

clean:
	rm -rf $(BUILD_DIR)

test:
	go test -v ./...

docker-build:
	docker build -t $(APP_NAME) .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f user_service
