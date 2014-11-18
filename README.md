MySQL/OTP
=========

This is a MySQL driver for Erlang following the OTP principles.

Status: Work in progress. Connecting and executing queries using the text protocol (plain queries) and binary protocols (prepared statements) work. The API and the value representation are subjects to change.

Background: We are starting this project with the aim at overcoming the problems with Emysql (the currently most popular driver) and erlang-mysql-driver (the even older driver).

Design choices:

* A connection is a gen_server.
* No connection pool. Poolboy or your own supervisor can be used for this.
* No records in the public API.
* API inspired by that of epgsql (the PostgreSQL driver).

Contributing
------------

We welcome contributors and new members of the project. We are open for suggestions about the API, the internal design and almost anything else. Let's use the project's wiki for discussions and TODOs.

Synopsis
--------

```Erlang
Opts = [{host, "localhost"}, {user, "foo"}, {password, "hello"},
        {database, "test"}],

%% This will probably be renamed to start_link/1
{ok, Pid} = mysql:connect(Opts),

%% A query returning results
{ok, ColumnNames, Rows} = mysql:query(Pid, <<"SELECT * FROM mytable">>),

%% A query not returning any rows just returns ok.
ok = mysql:query(Pid, "INSERT INTO mytable (foo, bar) VALUES (1, 42)"),

%% Named prepared statements. Maybe the function should be execute/3
%% instead of query/3.
{ok, foo} = mysql:prepare(Pid, "SELECT * FROM mytable WHERE id=?", foo),
{ok, Columns, Rows} = mysql:query(Pid, foo, [42]),

%% Unnamed prepared statements. The function query/3 will maybe be
%% renamed to execute/3.
{ok, StmtId} = mysql:prepare(Pid, "SELECT * FROM mytable WHERE id=?"),
{ok, Columns, Rows} = mysql:query(Pid, StmtId, [42]).

%% Separate calls to fetch more info about the last query
LastInsertId = mysql:insert_id(Pid),
AffectedRows = mysql:affected_rows(Pid),
WarningCount = mysql:warning_count(Pid),

%% An "anonymous prepared statement" with parameters, prepared and executed
%% on the fly. NOT IMPLEMENTED YET.
{ok, ColumnNames, Rows} =
    mysql:query(Pid, <<"SELECT * FROM mytable WHERE id=?">>, [42]),

%% Transactions: If an exception (throw/error/exit) occurs, the transaction
%% is rollbacked without catching the exception. This means transactions are
%% transparent to error handling. NOT IMPLEMENTED YET.
try
    mysql:transaction(
        Pid,
        fun () ->
            ok = mysql:query(Pid, "INSERT INTO mytable (foo) VALUES (1)"),
            throw(foo),
            ok = mysql:query(Pid, "INSERT INTO mytable (foo) VALUES (1)")
        end
    )
catch
    throw:foo ->
        %% Foo occurred. Fortunately nothing was stored.
        foo_occured
end.
```

Value representation
--------------------

 MySQL              | Erlang                  | Examples
--------------------|-------------------------|-------------------
INT, TINYINT, etc.  | integer()               | 42
VARCHAR, TEXT, etc. | iodata()                | <<"foo">>, "bar"
FLOAT, DOUBLE       | float()                 | 3.14
DECIMAL             | binary()                | <<"3.140">>
DATETIME, TIMESTAMP | calendar:datetime()     | {{2014, 11, 18}, {10, 22, 36}}
DATE                | calendar:date()         | {2014, 11, 18}
TIME                | {time, calendar:time()} | {time, {10, 22, 36}} -- **will probably change**
NULL                | null                    | null

Problems with Emysql
--------------------

From the Emysql README:

> The driver has several technical shortcomings:
>
> * No clear protocol / connection pool separation
> * No clear protocol / socket separation
> * A very complicated connection pool management
> * Uses the textual protocol in a lot of places where it shouldthe binary protocol
> * The API could be better
>
>However, this is probably the best MySQL driver out there for Erlang. The erlang-mysql-driver uses a problematic connection pool design for many use cases and is not suitable for general purpose use. This driver is.

License
-------

GNU General Public License (GPL) version 3 or any later version. See the LICENSE file.
