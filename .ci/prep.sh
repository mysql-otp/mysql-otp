#!/bin/bash

set -euo pipefail

set -x
export MYSQL_IMAGE="${MYSQL_IMAGE:-mysql:8.0}"
export MYSQL_CERTS_DIR='/etc/mysql_certs'

mkdir -p .ci/run .ci/certs
SSLDIR=/etc/mysql_certs make tests-prep
sudo cp test/ssl/ca.pem .ci/certs/
sudo mv test/ssl/server-key.pem .ci/certs/
sudo mv test/ssl/server-cert.pem .ci/certs/
mv test/ssl/my-ssl.cnf .ci/
sudo chmod 660 .ci/certs/*

# the host has no mysql user, issue a docker run command to change owner
docker run --rm -t -v $(pwd)/.ci/certs:${MYSQL_CERTS_DIR} ${MYSQL_IMAGE} chown -R mysql:mysql ${MYSQL_CERTS_DIR}
# now start mysql with config files and certificate files mouted as volumes
docker compose -f .ci/docker-compose.yml up -d --wait
# finally initialize test users
docker exec mysql /init.sh
