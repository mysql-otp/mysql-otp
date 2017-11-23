.PHONY: all clean

SSLDIR ?= $(shell pwd)
CAKEY = ca.key
CACERT = ca.pem
SERVERKEY = server-key.pem
SERVERCSR = server.csr
SERVERCERT = server-cert.pem

CASTRING = "/C=PL/L=Krakow/CN=MYSQL CA"
SERVERSTRING = "/C=PL/L=Krakow/CN=localhost"

all: my-ssl.cnf

my-ssl.cnf:
	openssl genrsa -out $(CAKEY) 2048
	openssl req -x509 -new -nodes -key $(CAKEY) -sha256 -days 1024 -out $(CACERT) -subj $(CASTRING)
	openssl genrsa -out $(SERVERKEY) 2048
	openssl req -new -key $(SERVERKEY) -out $(SERVERCSR) -subj $(SERVERSTRING)
	openssl x509 -req -in $(SERVERCSR) -CA $(CACERT) -CAkey $(CAKEY) -CAcreateserial -out $(SERVERCERT) -days 500 -sha256
	cp my-ssl.cnf.template my-ssl.cnf
	sed -i -e "s~%%CACERT%%~$(SSLDIR)/$(CACERT)~g" my-ssl.cnf
	sed -i -e "s~%%SERVERCERT%%~$(SSLDIR)/$(SERVERCERT)~g" my-ssl.cnf
	sed -i -e "s~%%SERVERKEY%%~$(SSLDIR)/$(SERVERKEY)~g" my-ssl.cnf

clean:
	rm -f ca*
	rm -f server*
	rm -f my-ssl.cnf my-ssl.cnf-e
