NO_COLOR=\033[0m
OK_COLOR=\033[32;01m
ERROR_COLOR=\033[31;01m
WARN_COLOR=\033[33;01m

CERT_DIR=certs
RSA_CSR="$(CERT_DIR)/idp.csr"
RSA_CRT="$(CERT_DIR)/idp.crt"
RSA_KEY="$(CERT_DIR)/idp.key"
RSA_INFO="/C=US/ST=New York/L=New York/O=ABC Inc./OU=IT/CN=idp.example.org"

default: build

build: vet
	@echo "$(OK_COLOR)==> Go Building(NO_COLOR)"
	go build ./...

init:
	go get github.com/nu7hatch/gouuid
	go get github.com/kardianos/osext
	go get github.com/stretchr/testify/assert

certs:
	mkdir -p $(CERT_DIR)
	openssl req -new -newkey rsa:2048 -nodes -out $(RSA_CSR) -keyout $(RSA_KEY) -subj $(RSA_INFO)
	openssl x509 -req -days 365 -in $(RSA_CSR) -signkey $(RSA_KEY) -out $(RSA_CRT)

vet: init
	@echo "$(OK_COLOR)==> Go Vetting$(NO_COLOR)"
	go vet ./...

test: vet
	@echo "$(OK_COLOR)==> Testing$(NO_COLOR)"
	go test ./...

clean:
	-rm -f $(CERT_DIR)/*

.PHONY: default build init test vet certs clean
