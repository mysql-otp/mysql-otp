#!/bin/bash

## This script is to create test users in MySQL or MariaDB for the tests to run.
## It is mainly to be executed in the docker container for GitHub Actions.
## But you may also use it to initialize a MySQL or MariaDB server running in local host.

## NOTE: this script is not re-enterable, only run it once.

set -euo pipefail

echo "Creating users for tests..."

if command -v mysql >/dev/null 2>&1; then
    CMD=mysql
else
    CMD=mariadb
fi

$CMD -uroot -e "CREATE USER 'otptest'@'%' IDENTIFIED BY 'OtpTest--123';"
$CMD -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptest'@'%';"
$CMD -uroot -e "CREATE USER 'otptest2'@'%' IDENTIFIED BY 'OtpTest2--123';"
$CMD -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptest2'@'%';"

# REQUIRE SSL must be specified only in CREATE USER in MySQL >= 8.0, only in GRANT in MySQL < 5.7;
# MySQL 5.7 allows both variants.
($CMD -uroot -e "CREATE USER 'otptestssl'@'%' IDENTIFIED BY 'OtpTestSSL--123' REQUIRE SSL;" &&
 $CMD -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptestssl'@'%';") ||
($CMD -uroot -e "CREATE USER 'otptestssl'@'%' IDENTIFIED BY 'OtpTestSSL--123';" &&
 $CMD -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptestssl'@'%' REQUIRE SSL;")

echo 'INIT-DONE'
