#!/bin/bash

## This script is to start MySQL or MariaDB in docker container
## for test cases to run.
## It is used in GitHub Actions, but can also be used to setup
## a test environment locally.
## Set MYSQL_IMAGE to mysql or mariadb
## And MYSQL_VERSION respectively

set -euo pipefail

if [ "${DEBUG:-0}" = 1 ]; then
    set -x
fi

export MYSQL_IMAGE="${MYSQL_IMAGE:-mysql}"
export MYSQL_VERSION="${MYSQL_VERSION:-8.4}"
export MYSQL_CERTS_DIR='/etc/mysql_certs'

BASEDIR="./scripts"

mkdir -p "${BASEDIR}/run" "${BASEDIR}/certs"
env SSLDIR=/etc/mysql_certs make -C test/ssl
mv test/ssl/my-ssl.cnf "${BASEDIR}/"
# Need to run with sudo here because later the files are changed to be owned by mysql user in docker container
# If the script is re-run (probably not in CI, but when running locally), cp without sudo will fail.
sudo cp test/ssl/ca.pem "${BASEDIR}/certs/"
sudo mv test/ssl/server-key.pem "${BASEDIR}/certs/"
sudo mv test/ssl/server-cert.pem "${BASEDIR}/certs/"
sudo chmod 660 "${BASEDIR}"/certs/*

if [ "${MYSQL_VERSION}" = '8.4' ]; then
    echo 'mysql_native_password=on' >> "${BASEDIR}/my-ssl.cnf"
fi

# the host has no mysql user, issue a docker run command to change owner
docker run --rm -t -v "$(pwd)/${BASEDIR}/certs:${MYSQL_CERTS_DIR}" "${MYSQL_IMAGE}:${MYSQL_VERSION}" chown -R mysql:mysql "${MYSQL_CERTS_DIR}"
# now start mysql with config files and certificate files mouted as volumes
docker compose -f "${BASEDIR}"/docker-compose.yml up -d --wait

# wait for mysqld to be ready
is_mysqld_ready() {
    docker logs mysql 2>&1 | grep -qE 'socket:\s.+/run/.+port:\s3306'
}

MAX_ATTEMPTS=6
attempt=0
while ! is_mysqld_ready; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
        echo "Failed to connect to MySQL server after $MAX_ATTEMPTS attempts."
        exit 1
    fi
    echo "waiting for server to be ready $attempt.."
    sleep 5
done

# finally initialize test users
docker exec mysql /init.sh
