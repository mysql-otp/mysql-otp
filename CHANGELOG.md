Change log
==========


1.8.0
-----
* Tag version [2021-08-12 14:38:57 +0200]
* Tooling for publishing Hex package [2021-08-04 13:20:48 +0200]
* Add auth_plugin_name to the end of handshake response [2021-08-03 20:47:02 +0200]
* Add optional float-as-decimal encoding [2021-07-07 12:05:04 +0200]
* README: markdown syntax highlighting [2021-03-04 15:02:00 +0100]
* Fix timeout test case in MariaDB builds [2021-03-04 14:56:53 +0100]
* Update CHANGELOG.md [2020-10-12 10:43:39 +0200]

1.7.0
-----
* Update version [2020-10-12 10:39:45 +0200]
* Support LOAD DATA LOCAL revised (#168) [2020-09-28 11:49:41 +0200]
* Improve typing [2020-06-26 16:35:09 +0200]
* Default SNI to hostname for SSL connections [2020-06-15 14:05:48 +0200]
* Allow activation of experimental socket backend for inet/gen_tcp [2020-06-05 15:15:23 +0200]
* Ping response should not change connection state [2020-05-25 17:04:06 +0200]
* Update CHANGELOG.md [2020-01-06 19:34:09 +0100]

1.6.0
-----
* Update version [2020-01-06 19:21:50 +0100]
* Travis tests for MySQL 5.6, 5.7, 8.0 and MariaDB 10.3 [2020-01-06 11:02:23 +0100]
* Update tests to pass with MariaDB 10.3 [2020-01-03 17:00:15 +0100]
* Workaround for changed deadlock handling in MySQL 5.7+ [2019-12-29 00:26:14 +0100]
* Fix MariaDB by not checking server capability CLIENT_LONG_PASSWORD [2019-12-28 22:54:03 +0100]
* Update README.md [2019-12-28 14:53:32 +0100]
* Edit documentation (edoc) [2019-12-28 14:53:32 +0100]
* Implement caching_sha2_password authentication [2019-12-28 14:38:46 +0100]
* Log slow queries [2019-12-21 20:03:15 +0100]
* Fix race conditions in change user tests [2019-12-17 18:54:28 +0100]
* Examine final EOF packet following resultset rows [2019-12-11 17:12:03 +0100]
* Override mode, packet and active TCP options (#148) [2019-12-10 13:08:13 +0100]
* Add kernel, stdlib and ssl to .app applications [2019-11-25 15:10:03 +0100]
* Enable connect modes: synchronous (default), asynchronous and lazy [2019-11-14 17:31:31 +0100]
* Normal exit when tcp_closed (#139) [2019-10-23 01:26:44 +0200]
* Check logged errors in tests and hide them from the output [2019-10-16 01:18:02 +0200]
* support 'COM_RESET_CONNECTION' (#138) [2019-10-15 10:32:58 +0200]
* Disable the deadlock test for MySQL 5.7.x [2019-10-14 21:24:27 +0200]
* Fix 'Access denied' test case failing on MariaDB [2019-09-21 23:12:31 +0200]
* Update CHANGELOG.md [2019-09-20 20:51:36 +0200]

1.5.1
-----
* Info about hex and mix in README and update version [2019-09-20 20:50:05 +0200]
* Move on-connect queries and prepares into mysql_conn [2019-06-03 16:26:09 +0200]
* test erlang/otp 22.0 [2019-05-23 18:43:56 +0200]
* Add ssl options to start_link/1 spec and doc [2019-05-06 23:52:16 +0200]
* Enable TCP option 'nodelay' [2019-04-25 01:18:30 +0200]
* Make TCP buffer at least as large as recbuf by default [2019-04-25 00:28:58 +0200]
* Use utf8mb4 for servers that support it [2019-04-24 19:38:27 +0200]
* Add tcp_options to start_link/1 spec [2019-04-24 18:46:09 +0200]
* Ignore SERVER_STATUS_AUTOCOMMIT on handshake [2019-04-03 19:39:51 +0200]
* Stop connection again when post-connect queries or prepares fail (#115) [2019-04-03 00:32:39 +0200]
* Default port 0 for unix socket [2019-04-01 17:51:43 +0200]

1.5.0
-----
* Update version and CHANGELOG.md [2019-03-31 18:56:42 +0200]
* Parameter validation for prepared statements and parameterized queries [2019-03-31 18:24:59 +0200]
* Synchronous stop [2019-03-31 18:24:59 +0200]
* Workaround for sub binary optimization bug in OTP 21.0 [2019-03-31 18:24:59 +0200]
* replace atom() with module() for SockModule parameters [2019-03-31 18:24:59 +0200]
* implement COM_CHANGE_USER (#105) [2019-03-31 18:24:59 +0200]
* Possibility to apply a filtermap fun on results (#104) [2019-03-31 18:24:59 +0200]
* Update version and CHANGELOG.md [2019-03-31 18:24:59 +0200]
* Get rid of socket wrapper modules [2019-03-31 18:24:59 +0200]
* Remove redundant transaction level info in state [2019-03-31 18:24:59 +0200]
* Remove superfluos 'Too many connections' test [2019-03-31 18:24:59 +0200]
* Move gen_server to separate module [2019-03-31 18:24:59 +0200]
* Handle error packet as the initial packet from the server [2019-03-31 18:24:59 +0200]
* Clarifications for usage with MySQL 8 [2019-03-31 18:24:22 +0200]
* Monitor calling process during transaction [2019-03-31 18:24:03 +0200]

1.4.0
-----
* Update version and CHANGELOG.md [2019-01-11 23:15:48 +0100]
* Get rid of socket wrapper modules [2018-12-03 01:07:39 +0100]
* Remove redundant transaction level info in state [2018-12-02 22:39:36 +0100]
* Remove superfluos 'Too many connections' test [2018-12-02 20:53:07 +0100]
* Move gen_server to separate module [2018-12-02 20:46:33 +0100]
* Handle error packet as the initial packet from the server [2018-12-02 18:35:45 +0100]
* Clarifications for usage with MySQL 8 [2018-12-02 15:31:25 +0100]
* Monitor calling process during transaction [2018-11-29 18:22:30 +0100]
* Run tests with verbose output by default [2018-11-27 20:58:15 +0100]
* fix spec for host option [2018-11-27 18:25:44 +0100]
* Mention exit(Pid, normal) in README and a test [2018-11-21 00:59:25 +0100]
* Return an error on deadlock if all retries fail in a transaction [2018-10-07 20:35:39 +0200]
* Set gen_server-timeouts for transaction statements to infinity (#91) [2018-10-06 21:39:14 +0200]

1.3.3
-----
* Compatibility with OTP 21.1 (#84) [2018-10-02 18:23:43 +0200]
* Don't restart transaction on lock wait timeout (#89) [2018-09-18 11:10:57 +0200]
* Make the Travis CI status show the master branch [2018-07-01 00:33:10 +0200]
* Update README.md [2018-04-13 04:33:52 +0200]
* Fixed a Typo in the doc [2018-03-21 11:13:26 +0100]
* Update CHANGELOG.md [2018-03-20 02:44:37 +0100]

1.3.2
-----
* Rewrite add_packet_headers and update version [2018-03-20 02:42:43 +0100]
* Sending packets with size greater than 16#ffffff (#77) [2018-03-20 00:16:48 +0100]
* Update CHANGELOG.md [2018-01-05 07:28:11 +0100]

1.3.1
-----
* Update .app.src file and README for version 1.3.1 [2018-01-05 07:26:58 +0100]
* Check handshake status, ignoring bit 16#4000, SERVER_SESSION_STATE_CHANGED [2017-12-28 17:29:40 +0100]
* Ignore mysql.d [2017-12-28 17:29:40 +0100]
* Compatible with MySQL 5.7 and MariaDB 10.2.6+ [2017-12-28 17:29:40 +0100]
* Update README again [2017-11-23 22:36:34 +0100]
* Update README [2017-11-23 22:34:24 +0100]
* Move SSL tests to separate suite [2017-11-23 22:07:18 +0100]
* Linebreak long lines [2017-11-23 22:05:51 +0100]
* Update erlang.mk and fix dialyzer plt apps [2017-11-23 22:04:39 +0100]
* Update changelog 1.3.0 [2017-11-23 21:57:57 +0100]

1.3.0
-----
* add erlang 20 for test [2017-09-21 13:32:38 +0200]
* Add SSL connection support [2017-09-21 13:28:43 +0200]
* Fix reading of unsigned integers in binary protocol [2017-08-02 00:09:54 +0200]
* fix mysql connect timeout. [2017-08-02 00:06:42 +0200]
* Add support for auth method switch [2017-08-02 00:05:04 +0200]
* Fix tests for MariaDB [2017-08-01 23:58:33 +0200]
* erlang 20 add floor/1 function, change the floor/1 funcion name in the self create module [2017-05-11 17:07:50 +0800]
* Add test for found_rows option. [2017-01-31 10:52:43 +0100]
* Allow setting CLIENT_FOUND_ROWS on handshake. [2017-01-31 10:45:17 +0100]
* Add Erlang 19 and 18 to Travis build matrix [2016-08-27 02:04:37 +0200]
* Add support for the MySQL JSON type [2016-08-27 01:41:43 +0200]
* Explicitly set the SQL mode to a known value [2016-07-23 13:08:13 +0200]
* Fix typo 'Gitbub' in docs [2016-07-01 15:44:29 +0200]
* Update CHANGELOG.md [2016-06-18 06:37:52 +0200]

1.2.0
-----
* Bump version to 1.2.0 [2016-06-18 06:37:07 +0200]
* Add test for server disconnect and tcp error [2016-06-18 06:27:51 +0200]
* Fixes typo: Set active once after executing prepared statement [2016-06-18 06:27:43 +0200]
* Stop the gen_server when mysql server closes connection [2016-06-11 16:11:06 +0200]
* Properly handling empty passwords [2016-02-19 16:41:09 -0800]
* this change required for the elixir/exrm to package this as a dependency. [2016-01-05 12:40:41 -0600]

1.1.1
-----
* Bumb version 1.1.1 [2015-09-13 12:09:33 +0200]
* Skip lock wait timeout test when setting the timeout is not possible [2015-09-13 11:56:57 +0200]
* Don't check the multi capabilities from the server; fixes #31 [2015-09-13 11:55:46 +0200]
* Update CHANGELOG.md [2015-08-31 16:39:43 +0200]

1.1.0
-----
* Bump version 1.1.0 and update README [2015-08-31 14:51:56 +0200]
* add decode_binary clause for floats with value 0.0 [2015-08-30 20:45:47 +0200]
* Edit docs and tests for unicode chardata as input [2015-08-27 16:17:09 +0200]
* add encoding declaration [2015-08-25 12:13:57 +0200]
* add unicode encoding to mysql:encode, update docs and add test [2015-08-25 11:45:06 +0200]
* Support for strings as prepared statement parameters [2015-08-19 12:19:22 +0200]
* Update CHANGELOG.md [2015-05-25 16:26:02 +0200]

1.0.0
-----
* Bump version to 1.0.0 [2015-05-25 16:24:28 +0200]
* Simplify parsing server version [2015-05-25 16:11:15 +0200]
* Use erlang.mk for tests and coverage report [2015-05-25 15:13:29 +0200]
* Update erlang.mk [2015-05-25 15:10:56 +0200]
* Add CHANGELOG.md and a make target to build it. [2015-04-10 14:20:01 +0200]
* Add test case for initial queries returning results that are discarded. [2015-04-09 18:35:04 +0200]

0.9.0
-----
* Bump version. [2015-04-09 18:08:58 +0200]
* Allow empty auth plugin name in handshake. [2015-04-09 18:01:41 +0200]
* Implement multiple statements and multiple result sets. [2015-04-02 13:56:09 +0200]
* Add applications entry to .app.src file needed for relx. [2015-04-02 13:53:38 +0200]
* add compartibility with mysql versions like 5.5.33a [2015-04-01 19:52:22 +0200]
* Timeouts on fetching warnings and fetching results of cancelled queries. [2015-03-10 12:19:40 +0100]
* Version update in deps examples [2015-02-25 13:52:09 +0100]

0.8.1
-----
* Global replace in mysql:encode/2 fixes #15 [2015-01-15 11:50:18 +0100]
* DEPS example [2015-01-13 00:00:37 +0100]
* Adds link to 'MySQL/OTP + Poolboy' [2015-01-09 17:26:35 +0100]

0.8.0
-----
* Bump version [2015-01-09 14:56:55 +0100]
* Option for extra TCP options [2015-01-07 12:04:09 +0100]
* README: Usage as dependency [2015-01-07 12:02:58 +0100]
* Fix warning for unused variable [2015-01-07 12:01:43 +0100]
* Execute qeries and prepared statements on connect [2015-01-05 15:47:30 +0100]
* Small change in usage example [2014-12-29 16:39:11 +0100]
* mysql:encode/2 with tests [2014-12-29 15:00:50 +0100]
* Fixes dialyzer warnings + removes unused stuff [2014-12-28 13:16:37 +0100]

0.7.1
-----
* Minor typos in docs and tests [2014-12-19 23:15:42 +0100]

0.7.0
-----
* Bump version 0.7.0 [2014-12-19 21:31:39 +0100]
* More tests fixes #2 [2014-12-19 21:29:45 +0100]
* Keep alive (ping) [2014-12-19 17:14:03 +0100]
* Simplify error handling for implicit commit [2014-12-19 12:22:10 +0100]
* Named EUnit test cases [2014-12-18 20:27:49 +0100]
* Test that warnings are logged [2014-12-18 20:15:08 +0100]
* Restartable transactions and implicit commits and rollbacks, fixes #7 [2014-12-18 19:57:19 +0100]
* Typo in edoc [2014-12-18 19:55:04 +0100]
* Disable logging of most warnings in tests [2014-12-17 02:20:01 +0100]
* Minor change + more time to timeout sensitive test [2014-12-17 02:07:04 +0100]
* Log warnings [2014-12-17 01:00:12 +0100]

0.6.0
-----
* Bump version 0.6.0 (nested transactions) [2014-12-16 18:46:13 +0100]
* Nested transactions [2014-12-16 18:45:26 +0100]

0.5.1
-----
* Patch version [2014-12-15 23:05:49 +0100]
* More test cases; coverage to 96% [2014-12-15 23:05:30 +0100]
* Compatibility with erlang.mk [2014-12-15 22:21:28 +0100]
* Adds missing test helper module [2014-12-15 18:38:51 +0100]

0.5.0
-----
* Bump version 0.5.0 [2014-12-13 23:16:28 +0100]
* Graceful timeout handling using KILL QUERY [2014-12-13 23:03:43 +0100]
* Avoid dict:is_empty/1 for compat with old OTP versions [2014-12-10 23:13:11 +0100]
* Add parametrized queries to README [2014-12-10 23:06:33 +0100]
* Parametrized queries using cached prep. stmts [2014-12-10 22:59:54 +0100]
* docs and specs [2014-12-10 22:39:41 +0100]
* Fixes test for R16B by avoiding sys:get_state/1 [2014-12-09 13:30:00 +0100]
* Implements selecting db in the connection phase [2014-12-09 10:47:15 +0100]
* Merges mysql_connection with mysql [2014-12-09 10:08:36 +0100]

0.4.0
-----
* Bump version 0.4.0: changed value representation for some types [2014-12-08 02:00:30 +0100]
* DECIMAL(P,S) as int/float/binary depending on P and S [2014-12-08 01:41:41 +0100]
* Implements BIT(N) <--> bitstring() of length N [2014-12-07 19:53:30 +0100]
* Fixes decode TINYINT as signed in binary protocol [2014-12-07 19:12:31 +0100]
* Refactoring [2014-12-07 19:11:11 +0100]

0.3.0
-----
* Bump version 0.3.0 [2014-12-04 00:40:23 +0100]
* Add option {name, ServerName} and mysql_connection:start_link/1 [2014-12-04 00:36:25 +0100]
* Send goodbye when terminating [2014-12-03 10:49:06 +0100]
* Minor text changes [2014-12-03 01:13:41 +0100]
* Named prepared statements + unprepare/2 + {error, not_prepared} for execute/3 [2014-12-03 01:11:35 +0100]
* Makefile rules for gh-pages [2014-12-01 22:46:57 +0100]
* Documentation [2014-12-01 02:06:34 +0100]

0.2.0
-----
* Add autocommit/1 [2014-11-30 17:00:50 +0100]
* in_transaction/1 (related to #7) [2014-11-30 16:42:34 +0100]
* Edoc and spec [2014-11-30 15:46:15 +0100]
* Implements simple mnesia style transactions (#7) [2014-11-29 22:51:42 +0100]
* Changed transaction example [2014-11-29 12:56:57 +0100]
* Notes about LGPL + logo fix [2014-11-28 22:17:51 +0100]
* Change license to LGPL [2014-11-28 21:05:48 +0100]
* Set up Travis build [2014-11-27 03:03:34 +0100]
* Typo in travis file [2014-11-27 02:03:58 +0100]
* Adds travis ci file [2014-11-27 02:00:56 +0100]
* Adds note on license compatibility issues [2014-11-25 19:06:28 +0100]

0.1.1
-----
* Patch version [2014-11-27 01:25:41 +0100]
* Error message formatting [2014-11-27 01:24:00 +0100]
* Fixes handshake for servers without CLIENT_PLUGIN_AUTH [2014-11-27 01:23:33 +0100]
* EDoc overview page and custom CSS [2014-11-25 02:07:53 +0100]

0.1.0
-----
* Bump version [2014-11-24 22:46:34 +0100]
* Negative TIME, microseconds in TIME and DATETIME, new TIME representation [2014-11-24 22:45:24 +0100]
* How to run the tests [2014-11-23 13:04:21 +0100]
* Renames some functions [2014-11-20 19:33:44 +0100]
* Update README.md [2014-11-18 10:26:44 +0100]
* Update README.md [2014-11-18 10:09:43 +0100]
* Float rounding; see #4 [2014-11-18 09:28:46 +0100]
* Binary protocol [2014-11-15 19:25:27 +0100]
* Adds a failing test for float (precicion loss) [2014-11-05 09:30:24 +0100]
* Refactoring [2014-11-05 09:12:18 +0100]
* Prepared statements without params (bin protocol) [2014-11-04 22:03:09 +0100]
* Add licence information [2014-11-04 18:01:53 +0100]
* Test for password hash [2014-11-03 00:14:41 +0100]
* Prepared statements partially + various fixes [2014-11-02 23:52:02 +0100]
* Use the timeout option in all TCP recv calls [2014-11-02 22:47:26 +0100]
* Comments and errors [2014-11-02 22:46:40 +0100]
* Implement plain queries and the text protocol [2014-11-02 16:19:41 +0100]
* Update README.md [2014-10-28 22:25:12 +0100]
* Implements handshake and basic protocol [2014-10-28 16:44:14 +0100]
* Initial commit [2014-10-28 16:38:08 +0100]
