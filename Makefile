VERSION := `git describe --tags`

process_exporter: process_exporter.go
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" process_exporter.go

clean:
	rm -f process_exporter

.PHONY: clean
