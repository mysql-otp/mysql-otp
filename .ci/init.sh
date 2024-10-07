#!/bin/bash

set -euo pipefail

MAX_ATTEMPTS=15
attempt=0
while ! mysql -uroot -e 'show databases;' >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    echo "Waiting for MySQL... $attempt"
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
        echo "Failed to connect to MySQL server after $MAX_ATTEMPTS attempts."
        exit 1
    fi
    sleep 1
done

echo "Creating users for tests..."

mysql -uroot -e "CREATE USER 'otptest'@'%' IDENTIFIED BY 'OtpTest--123';"
mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptest'@'%';"
mysql -uroot -e "CREATE USER 'otptest2'@'%' IDENTIFIED BY 'OtpTest2--123';"
mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptest2'@'%';"

# REQUIRE SSL must be specified only in CREATE USER in MySQL >= 8.0, only in GRANT in MySQL < 5.7;
# MySQL 5.7 allows both variants.
(mysql -uroot -e "CREATE USER 'otptestssl'@'%' IDENTIFIED BY 'OtpTestSSL--123' REQUIRE SSL;" &&
 mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptestssl'@'%';") ||
(mysql -uroot -e "CREATE USER 'otptestssl'@'%' IDENTIFIED BY 'OtpTestSSL--123';" &&
 mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO 'otptestssl'@'%' REQUIRE SSL;")

echo 'INIT-DONE'
