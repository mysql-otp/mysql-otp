MySQL/OTP
=========

[![Build Status](https://travis-ci.org/mysql-otp/mysql-otp.svg?branch=master)](https://travis-ci.org/mysql-otp/mysql-otp)
 :link: [Test coverage (EUnit)](//mysql-otp.github.io/mysql-otp/eunit.html)
 :link: [API documentation (EDoc)](//mysql-otp.github.io/mysql-otp/index.html)

MySQL/OTP is a driver for connecting Erlang/OTP applications to MySQL and
MariaDB databases. It is a native implementation of the MySQL protocol in
Erlang.

Some of the features:

* Mnesia style transactions:
  * Nested transactions are implemented using SQL savepoints.
  * Transactions are automatically retried when deadlocks are detected.
* Each connection is a gen_server, which makes it compatible with Poolboy (for
  connection pooling) and ordinary OTP supervisors.
* No records in the public API.
* SSL.
* Parametrized queries using cached prepared statements
  ([What?](https://github.com/mysql-otp/mysql-otp/wiki/Parametrized-queries-using-cached-prepared-statements))
* Slow queries are interrupted without killing the connection (MySQL version
  ≥ 5.0.0)
* Implements both protocols: the binary protocol for prepared statements and
  the text protocol for plain queries.

Requirements:

* Erlang/OTP version R16B or later, excluding 21.0 which has a bug in binary
  pattern matching. This was fixed in OTP 21.1.
* MySQL database version 4.1 or later or MariaDB
* No other dependencies
* Authentication method `caching_sha2_password` is not supported. This is the
  default in MySQL 8.0.4 and later, so you need to add
  `default_authentication_plugin=mysql_native_password` under `[mysqld]` in e.g.
  `/etc/mysql/my.cnf`.

Synopsis
--------

```Erlang
%% Connect (ssl is optional)
{ok, Pid} = mysql:start_link([{host, "localhost"}, {user, "foo"},
                              {password, "hello"}, {database, "test"},
                              {ssl, [{server_name_indication, disable},
                                     {cacertfile, "/path/to/ca.pem"}]}]),

%% Select
{ok, ColumnNames, Rows} =
    mysql:query(Pid, <<"SELECT * FROM mytable WHERE id = ?">>, [1]),

%% Manipulate data
ok = mysql:query(Pid, "INSERT INTO mytable (id, bar) VALUES (?, ?)", [1, 42]),

%% Separate calls to fetch more info about the last query
LastInsertId = mysql:insert_id(Pid),
AffectedRows = mysql:affected_rows(Pid),
WarningCount = mysql:warning_count(Pid),

%% Mnesia style transaction (nestable)
Result = mysql:transaction(Pid, fun () ->
    ok = mysql:query(Pid, "INSERT INTO mytable (foo) VALUES (1)"),
    throw(foo),
    ok = mysql:query(Pid, "INSERT INTO mytable (foo) VALUES (1)")
end),
case Result of
    {atomic, ResultOfFun} ->
        io:format("Inserted 2 rows.~n");
    {aborted, Reason} ->
        io:format("Inserted 0 rows.~n")
end

%% Multiple queries and multiple result sets
{ok, [{[<<"foo">>], [[42]]}, {[<<"bar">>], [[<<"baz">>]]}]} =
    mysql:query(Pid, "SELECT 42 AS foo; SELECT 'baz' AS bar;"),

%% Graceful timeout handling: SLEEP() returns 1 when interrupted
{ok, [<<"SLEEP(5)">>], [[1]]} =
    mysql:query(Pid, <<"SELECT SLEEP(5)">>, 1000),

%% Close the connection; make it exit normally
exit(Pid, normal).
```

Usage as a dependency
---------------------

Using *erlang.mk*:

    DEPS = mysql
    dep_mysql = git https://github.com/mysql-otp/mysql-otp 1.4.0

Using *rebar*:

    {deps, [
        {mysql, ".*", {git, "https://github.com/mysql-otp/mysql-otp",
                       {tag, "1.4.0"}}}
    ]}.

Tests
-----

EUnit tests are executed using `make tests` or `make eunit`.

To run individual test suites, use `make eunit t=SUITE` where SUITE is one of
`mysql_encode_tests`, `mysql_protocol_tests`, `mysql_tests`, `ssl_tests` or
`transaction_tests`.

The encode and protocol test suites does not require a
running MySQL server on localhost.

For the suites `mysql_tests`, `ssl_tests` and `transaction_tests` you need to
start MySQL on localhost and give privileges to the user `otptest` and (for
`ssl_tests`) to the user `otptestssl`:

```SQL
CREATE USER otptest@localhost IDENTIFIED BY 'otptest';
GRANT ALL PRIVILEGES ON otptest.* TO otptest@localhost;

CREATE USER otptestssl@localhost IDENTIFIED BY 'otptestssl';
GRANT ALL PRIVILEGES ON otptest.* TO otptestssl@localhost REQUIRE SSL;
```

Before running the test suite `ssl_tests` you'll also need to generate SSL files
and MySQL extra config file. In order to do so, please execute `make tests-prep`.

The MySQL server configuration must include `my-ssl.cnf` file,
which can be found in `test/ssl/`.
**Do not run** `make tests-prep` after you start MySQL,
because CA certificates will no longer match.

If you run `make tests COVER=1` a coverage report will be generated. Open
`cover/index.html` to see that any lines you have added or modified are covered
by a test.

Contributing
------------

Run the tests and also dialyzer using `make dialyze`.

Linebreak code to 80 characters per line and follow a coding style similar to
that of existing code.

Keep commit messages short and descriptive. Each commit message should describe
the purpose of the commit, the feature added or bug fixed, so that the commit
log can be used as a comprehensive change log. [CHANGELOG.md](CHANGELOG.md) is
generated from the commit messages.

Maintaining
-----------

This is for the project's maintainer(s) only.

Tagging a new version:

1. Before tagging, update src/mysql.app.src and README.md with the new version.
2. Tag and push tags using `git push --tags`.
3. After tagging a new version:
  * Update the changelog using `make CHANGELOG.md` and commit it.
  * Update the online documentation and coverage reports using `make gh-pages`.
    Then push the gh-pages branch using `git push origin gh-pages`.

License
-------

GNU Lesser General Public License (LGPL) version 3 or any later version.
Since the LGPL is a set of additional permissions on top of the GPL, both
license texts are included in the files [COPYING](COPYING) and
[COPYING.LESSER](COPYING.LESSER) respectively.

We hope this license should be permissive enough while remaining copyleft. If
you're having issues with this license, please create an issue in the issue
tracker!
