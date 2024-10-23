MySQL/OTP
=========

 :link: [Test coverage (EUnit)](//mysql-otp.github.io/mysql-otp/eunit.html)
 :link: [API documentation (EDoc)](//mysql-otp.github.io/mysql-otp/index.html)
 :link: [Hex package](//hex.pm/packages/mysql)

MySQL/OTP is a driver for connecting Erlang/OTP applications to MySQL and
MariaDB databases. It is a native implementation of the MySQL protocol in
Erlang.

Some of the features:

* Mnesia style transactions:
  * Nested transactions are implemented using SQL savepoints.
  * Transactions are automatically retried when deadlocks are detected.
* Each connection is a gen_server, which makes it compatible with Poolboy (for
  connection pooling) and ordinary OTP supervisors.
* SSL.
* Authentication methods `caching_sha2_password` (default from MySQL 8.0.4) and
  `mysql_native_password` (default from MySQL 4.1).
* Parametrized queries using cached unnamed prepared statements
  ([What?](https://github.com/mysql-otp/mysql-otp/wiki/Parametrized-queries-using-cached-prepared-statements))
* Slow queries are interrupted without killing the connection (MySQL version
  ≥ 5.0.0)
* Implements both protocols: the binary protocol for prepared statements and
  the text protocol for plain queries.

Requirements:

* Erlang/OTP version 19 or later
* MySQL database version 4.1 or later or MariaDB
* GNU Make *or* Rebar or any other tool for building Erlang/OTP applications

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
end,

%% Multiple queries and multiple result sets
{ok, [{[<<"foo">>], [[42]]}, {[<<"bar">>], [[<<"baz">>]]}]} =
    mysql:query(Pid, "SELECT 42 AS foo; SELECT 'baz' AS bar;"),

%% Graceful timeout handling: SLEEP() returns 1 when interrupted
{ok, [<<"SLEEP(5)">>], [[1]]} =
    mysql:query(Pid, <<"SELECT SLEEP(5)">>, 1000),

%% Close the connection
mysql:stop(Pid).
```

Usage as a dependency
---------------------

Using *erlang.mk*:

    DEPS = mysql
    dep_mysql = git https://github.com/mysql-otp/mysql-otp 1.8.0

Using *rebar* (version 2 or 3):

```erlang
{deps, [
  {mysql, ".*", {git, "https://github.com/mysql-otp/mysql-otp",
                {tag, "1.8.0"}}}
]}.
```

Using *mix*:

```elixir
{:mysql, git: "https://github.com/mysql-otp/mysql-otp", tag: "1.8.0"},
```

There's also a Hex package called [mysql](//hex.pm/packages/mysql).

Tests
-----

EUnit tests are executed using `make tests` or `make eunit`.

To run individual test suites, use `make eunit t=SUITE` where SUITE is one of
`mysql_encode_tests`, `mysql_protocol_tests`, `mysql_tests`, `ssl_tests` or
`transaction_tests`.

The encode and protocol test suites does not require a
running MySQL server on localhost.

To quickly setup MySQL or MariaDB runing in docker for testing,
execute `make tests-prep`, then execute `make tests`.

Set environemt variable `MYSQL_IMAGE=mysql|mariadb` and `MYSQL_VERSION` to pick a flavor.

To test aginast MySQL or MariaDB running in localhost, follow the below steps:

- Stop MySQL service
- Generate SSL certificates by running `make -C test/ssl`
- Copy `test/ssl/server-{cert,key}.pem` to `/etc/mysql/`
- Copy `test/ssl/ca.pem` to `/etc/mysql/`
- Change certificate file modes: `sudo chmod -R 660 /etc/mysql/*.pem`
- Change certificate file owner: `sudo chown mysql:mysql /etc/mysql/*.pem`
- Append SSL configs: `cat test/ssl/my-ssl.cnf | sudo tee -a /etc/mysql/conf.d/my-ssl.cnf`
- Start MySQL service
- Run `sudo ./scripts/init.sh` to prepare for test users.
  The script connects to the database on localhost as root and creates users.
  Alternatively, look into the script and perform the steps manually.
- Run `make tests`.

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

Updating the Hex package (requires Mix):

    make publish-hex

License
-------

GNU Lesser General Public License (LGPL) version 3 or any later version.
Since the LGPL is a set of additional permissions on top of the GPL, both
license texts are included in the files [COPYING](COPYING) and
[COPYING.LESSER](COPYING.LESSER) respectively.
