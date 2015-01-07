MySQL/OTP
=========

[![Build Status](https://travis-ci.org/mysql-otp/mysql-otp.svg)](https://travis-ci.org/mysql-otp/mysql-otp)

MySQL/OTP is a driver for connecting Erlang/OTP applications to MySQL
databases. It is a native implementation of the MySQL protocol in Erlang.

Some of the features:

* Mnesia style transactions:
  * Nested transactions are implemented using savepoints.
  * Transactions are automatically retried when deadlocks are detected.
* Uses the binary protocol for prepared statements.
* Each connection is a gen_server, which makes it compatible with Poolboy (for
  connection pooling) and ordinary OTP supervisors.
* No records in the public API.
* Slow queries are interrupted without killing the connection (MySQL version
  ≥ 5.0.0).

See also:

* [API documenation](//mysql-otp.github.io/mysql-otp/index.html) (Edoc)
* [Test coverage](//mysql-otp.github.io/mysql-otp/eunit.html) (EUnit)
* [Why another MySQL driver?](https://github.com/mysql-otp/mysql-otp/wiki#why-another-mysql-driver) in the wiki

This is a work in progress. Use a tagged version to make sure nothing breaks.

Synopsis
--------

```Erlang
%% Connect
{ok, Pid} = mysql:start_link([{host, "localhost"}, {user, "foo"},
                              {password, "hello"}, {database, "test"}]),

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

%% Graceful timeout handling: SLEEP() returns 1 when interrupted
{ok, [<<"SLEEP(5)">>], [[1]]} =
    mysql:query(Pid, <<"SELECT SLEEP(5)">>, 1000),
```

Usage as a dependency
---------------------

With *erlang.mk*:

    PROJECT = someproject
    DEPS = mysql-otp
    dep_mysql-otp = git https://github.com/mysql-otp/mysql-otp master
    include erlang.mk

With *rebar*:

    {deps, [
        {mysql, ".*", {git, "https://github.com/mysql-otp/mysql-otp",
                       {branch, "master"}}}
    ]}.

Tests
-----

Run the eunit tests with `make eunit`. The tests need an executable `rebar` in
the `$PATH`. For the suite `mysql_tests` you need MySQL running on localhost
and give privileges to the `otptest` user:

```SQL
grant all privileges on otptest.* to otptest@localhost identified by 'otptest';
```

Contributing
------------

Pull request and feature requests are welcome. If you're looking for something
to do, pick one of the issues and solve it. Remember to include test cases.

License
-------

GNU Lesser General Public License (LGPL) version 3 or any later version.
Since the LGPL is a set of additional permissions on top of the GPL, both
license texts are included in the files [COPYING](COPYING) and
[COPYING.LESSER](COPYING.LESSER) respectively.

We hope this license should be permissive enough while remaining copyleft. If
you're having issues with this license, please create an issue in the issue
tracker!
