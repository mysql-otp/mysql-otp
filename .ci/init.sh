#!/bin/bash

sudo mysql -uroot -e "CREATE USER otptest@localhost IDENTIFIED BY 'OtpTest--123';"
sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO otptest@localhost;"
sudo mysql -uroot -e "CREATE USER otptest2@localhost IDENTIFIED BY 'OtpTest2--123';"
sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO otptest2@localhost;"

# REQUIRE SSL must be specified only in CREATE USER in MySQL >= 8.0, only in GRANT in MySQL < 5.7;
# MySQL 5.7 allows both variants.
(sudo mysql -uroot -e "CREATE USER otptestssl@localhost IDENTIFIED BY 'OtpTestSSL--123' REQUIRE SSL;" &&
 sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO otptestssl@localhost;") ||
(sudo mysql -uroot -e "CREATE USER otptestssl@localhost IDENTIFIED BY 'OtpTestSSL--123';" &&
 sudo mysql -uroot -e "GRANT ALL PRIVILEGES ON otptest.* TO otptestssl@localhost REQUIRE SSL;")
