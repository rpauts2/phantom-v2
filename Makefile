build:
	go build -o phantom ./cmd/phantom
test:
	go test ./...
vet:
	go vet ./...
validate:
	go run ./cmd/phantom -validate -config config.yaml.example -phishlets configs/phishlets
