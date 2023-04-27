DEPS = $(go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)

all: deps
	@mkdir -p bin
	go build -o bin/nrped

deps:
	go mod tidy

test: deps
	go test ./...

check_nrpe: deps
	@mkdir -p bin
	go build -C check_nrpe -o ../bin/check_nrpe

clean:
	rm -rf bin
