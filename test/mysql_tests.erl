%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
%%
%% This file is part of MySQL/OTP.
%%
%% MySQL/OTP is free software: you can redistribute it and/or modify it under
%% the terms of the GNU Lesser General Public License as published by the Free
%% Software Foundation, either version 3 of the License, or (at your option)
%% any later version.
%%
%% This program is distributed in the hope that it will be useful, but WITHOUT
%% ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
%% FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
%% more details.
%%
%% You should have received a copy of the GNU Lesser General Public License
%% along with this program. If not, see <https://www.gnu.org/licenses/>.

%% @doc This module performs test to an actual database.
-module(mysql_tests).

-include_lib("eunit/include/eunit.hrl").

-define(user,     "otptest").
-define(password, "otptest").

-define(create_table_t, <<"CREATE TABLE t ("
                          "  id INT NOT NULL PRIMARY KEY AUTO_INCREMENT,"
                          "  bl BLOB,"
                          "  tx TEXT NOT NULL," %% No default value
                          "  f FLOAT,"
                          "  d DOUBLE,"
                          "  dc DECIMAL(5,3),"
                          "  y YEAR,"
                          "  ti TIME,"
                          "  ts TIMESTAMP,"
                          "  da DATE,"
                          "  c CHAR(2)"
                          ") ENGINE=InnoDB">>).

failing_connect_test() ->
    process_flag(trap_exit, true),
    ?assertMatch({error, {1045, <<"28000">>, <<"Access denied", _/binary>>}},
                 mysql:start_link([{user, "dummy"}, {password, "junk"}])),
    receive
        {'EXIT', _Pid, {1045, <<"28000">>, <<"Access denie", _/binary>>}} -> ok
    after 1000 ->
        ?assertEqual(ok, no_exit_message)
    end,
    process_flag(trap_exit, false).

successful_connect_test() ->
    %% A connection with a registered name and execute initial queries and
    %% create prepared statements.
    Options = [{name, {local, tardis}}, {user, ?user}, {password, ?password},
               {queries, ["SET @foo = 'bar'", "SELECT 1",
                          "SELECT 1; SELECT 2"]},
               {prepare, [{foo, "SELECT @foo"}]}],
    {ok, Pid} = mysql:start_link(Options),
    %% Check that queries and prepare has been done.
    ?assertEqual({ok, [<<"@foo">>], [[<<"bar">>]]},
                 mysql:execute(Pid, foo, [])),
    %% Test some gen_server callbacks not tested elsewhere
    State = get_state(Pid),
    ?assertMatch({ok, State}, mysql:code_change("0.1.0", State, [])),
    ?assertMatch({error, _}, mysql:code_change("2.0.0", unknown_state, [])),
    exit(whereis(tardis), normal).

keep_alive_test() ->
     %% Let the connection send a few pings.
     process_flag(trap_exit, true),
     Options = [{user, ?user}, {password, ?password}, {keep_alive, 20}],
     {ok, Pid} = mysql:start_link(Options),
     receive after 70 -> ok end,
     State = get_state(Pid),
     [state, _Version, _ConnectionId, tcp, Socket | _] = tuple_to_list(State),
     {ok, ExitMessage, LoggedErrors} = error_logger_acc:capture(fun () ->
         gen_tcp:close(Socket),
         receive
            Message -> Message
         after 1000 ->
             ping_didnt_crash_connection
         end
     end),
     process_flag(trap_exit, false),
     %% Check that we got the expected crash report in the error log.
     ?assertMatch({'EXIT', Pid, _Reason}, ExitMessage),
     [{error, LoggedMsg}, {error_report, LoggedReport}] = LoggedErrors,
     ExpectedPrefix = io_lib:format("** Generic server ~p terminating", [Pid]),
     ?assert(lists:prefix(lists:flatten(ExpectedPrefix), LoggedMsg)),
     ?assertMatch({crash_report, _}, LoggedReport),
     exit(Pid, normal).

%% For R16B where sys:get_state/1 is not available.
get_state(Process) ->
    {status,_,_,[_,_,_,_,Misc]} = sys:get_status(Process),
    hd([State || {data,[{"State", State}]} <- Misc]).

query_test_() ->
    {setup,
     fun () ->
         {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                       {log_warnings, false},
                                       {keep_alive, true}]),
         ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
         ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
         ok = mysql:query(Pid, <<"USE otptest">>),
         ok = mysql:query(Pid, <<"SET autocommit = 1">>),
         Pid
     end,
     fun (Pid) ->
         ok = mysql:query(Pid, <<"DROP DATABASE otptest">>),
         exit(Pid, normal)
     end,
     fun (Pid) ->
         [{"Select db on connect", fun () -> connect_with_db(Pid) end},
          {"Autocommit",           fun () -> autocommit(Pid) end},
          {"Encode",               fun () -> encode(Pid) end},
          {"Basic queries",        fun () -> basic_queries(Pid) end},
          {"Multi statements",     fun () -> multi_statements(Pid) end},
          {"Text protocol",        fun () -> text_protocol(Pid) end},
          {"Binary protocol",      fun () -> binary_protocol(Pid) end},
          {"FLOAT rounding",       fun () -> float_rounding(Pid) end},
          {"DECIMAL",              fun () -> decimal(Pid) end},
          {"INT",                  fun () -> int(Pid) end},
          {"BIT(N)",               fun () -> bit(Pid) end},
          {"DATE",                 fun () -> date(Pid) end},
          {"TIME",                 fun () -> time(Pid) end},
          {"DATETIME",             fun () -> datetime(Pid) end},
          {"Microseconds",         fun () -> microseconds(Pid) end}]
     end}.

connect_with_db(_Pid) ->
    %% Make another connection and set the db in the handshake phase
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {database, "otptest"}]),
    ?assertMatch({ok, _, [[<<"otptest">>]]},
                 mysql:query(Pid, "SELECT DATABASE()")),
    exit(Pid, normal).

log_warnings_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password}]),
    ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
    ok = mysql:query(Pid, <<"USE otptest">>),
    %% Capture error log to check that we get a warning logged
    ok = mysql:query(Pid, "CREATE TABLE foo (x INT NOT NULL)"),
    {ok, insrt} = mysql:prepare(Pid, insrt, "INSERT INTO foo () VALUES ()"),
    {ok, ok, LoggedErrors} = error_logger_acc:capture(fun () ->
        ok = mysql:query(Pid, "INSERT INTO foo () VALUES ()"),
        ok = mysql:query(Pid, "INSeRT INtO foo () VaLUeS ()", []),
        ok = mysql:execute(Pid, insrt, [])
    end),
    [{_, Log1}, {_, Log2}, {_, Log3}] = LoggedErrors,
    ?assertEqual("Warning 1364: Field 'x' doesn't have a default value\n"
                 " in INSERT INTO foo () VALUES ()\n", Log1),
    ?assertEqual("Warning 1364: Field 'x' doesn't have a default value\n"
                 " in INSeRT INtO foo () VaLUeS ()\n", Log2),
    ?assertEqual("Warning 1364: Field 'x' doesn't have a default value\n"
                 " in INSERT INTO foo () VALUES ()\n", Log3),
    exit(Pid, normal).

autocommit(Pid) ->
    ?assert(mysql:autocommit(Pid)),
    ok = mysql:query(Pid, <<"SET autocommit = 0">>),
    ?assertNot(mysql:autocommit(Pid)),
    ok = mysql:query(Pid, <<"SET autocommit = 1">>),
    ?assert(mysql:autocommit(Pid)).

encode(Pid) ->
    %% Test with backslash escapes enabled and disabled.
    {ok, _, [[OldMode]]} = mysql:query(Pid, "SELECT @@sql_mode"),
    ok = mysql:query(Pid, "SET sql_mode = ''"),
    ?assertEqual(<<"'foo\\\\bar''baz'">>,
                 iolist_to_binary(mysql:encode(Pid, "foo\\bar'baz"))),
    ok = mysql:query(Pid, "SET sql_mode = 'NO_BACKSLASH_ESCAPES'"),
    ?assertEqual(<<"'foo\\bar''baz'">>,
                 iolist_to_binary(mysql:encode(Pid, "foo\\bar'baz"))),
    ok = mysql:query(Pid, "SET sql_mode = ?", [OldMode]).

basic_queries(Pid) ->

    %% warning count
    ?assertEqual(ok, mysql:query(Pid, <<"DROP TABLE IF EXISTS foo">>)),
    ?assertEqual(1, mysql:warning_count(Pid)),

    %% SQL parse error
    ?assertMatch({error, {1064, <<"42000">>, <<"You have an erro", _/binary>>}},
                 mysql:query(Pid, <<"FOO">>)),

    %% Simple resultset with various types
    ?assertEqual({ok, [<<"i">>, <<"s">>], [[42, <<"foo">>]]},
                 mysql:query(Pid, <<"SELECT 42 AS i, 'foo' AS s;">>)),

    ok.

multi_statements(Pid) ->
    %% Multiple statements, no result set
    ?assertEqual(ok, mysql:query(Pid, "CREATE TABLE foo (bar INT);"
                                      "DROP TABLE foo;")),

    %% Multiple statements, one result set
    ?assertEqual({ok, [<<"foo">>], [[42]]},
                 mysql:query(Pid, "CREATE TABLE foo (bar INT);"
                                  "DROP TABLE foo;"
                                  "SELECT 42 AS foo;")),

    %% Multiple statements, multiple result sets
    ?assertEqual({ok, [{[<<"foo">>], [[42]]}, {[<<"bar">>], [[<<"baz">>]]}]},
                 mysql:query(Pid, "SELECT 42 AS foo; SELECT 'baz' AS bar;")),

    %% Multiple results in a prepared statement.
    %% Preparing "SELECT ...; SELECT ...;" gives a syntax error although the
    %% docs say it should be possible.

    %% Instead, test executing a stored procedure that returns multiple result
    %% sets using a prepared statement.

    CreateProc = "CREATE PROCEDURE multifoo() BEGIN\n"
                 "  SELECT 42 AS foo;\n"
                 "  SELECT 'baz' AS bar;\n"
                 "END;\n",
    ok = mysql:query(Pid, CreateProc),
    ?assertEqual({ok, multifoo},
                 mysql:prepare(Pid, multifoo, "CALL multifoo();")),
    ?assertEqual({ok, [{[<<"foo">>], [[42]]}, {[<<"bar">>], [[<<"baz">>]]}]},
                 mysql:execute(Pid, multifoo, [])),
    ?assertEqual(ok, mysql:unprepare(Pid, multifoo)),
    ?assertEqual(ok, mysql:query(Pid, "DROP PROCEDURE multifoo;")),

    ok.

text_protocol(Pid) ->
    ok = mysql:query(Pid, ?create_table_t),
    ok = mysql:query(Pid, <<"INSERT INTO t (bl, f, d, dc, y, ti, ts, da, c)"
                            " VALUES ('blob', 3.14, 3.14, 3.14, 2014,"
                            "'00:22:11', '2014-11-03 00:22:24', '2014-11-03',"
                            " NULL)">>),
    ?assertEqual(1, mysql:warning_count(Pid)), %% tx has no default value
    ?assertEqual(1, mysql:insert_id(Pid)),     %% auto_increment starts from 1
    ?assertEqual(1, mysql:affected_rows(Pid)),

    %% select
    {ok, Columns, Rows} = mysql:query(Pid, <<"SELECT * FROM t">>),
    ?assertEqual([<<"id">>, <<"bl">>, <<"tx">>, <<"f">>, <<"d">>, <<"dc">>,
                  <<"y">>, <<"ti">>, <<"ts">>, <<"da">>, <<"c">>], Columns),
    ?assertEqual([[1, <<"blob">>, <<>>, 3.14, 3.14, 3.14,
                   2014, {0, {0, 22, 11}},
                   {{2014, 11, 03}, {00, 22, 24}}, {2014, 11, 03}, null]],
                 Rows),

    ok = mysql:query(Pid, <<"DROP TABLE t">>).

binary_protocol(Pid) ->
    ok = mysql:query(Pid, ?create_table_t),
    %% The same queries as in the text protocol. Expect the same results.
    {ok, Ins} = mysql:prepare(Pid, <<"INSERT INTO t (bl, tx, f, d, dc, y, ti,"
                                     " ts, da, c)"
                                     " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)">>),
    %% 16#161 is the codepoint for "s with caron"; <<197, 161>> in UTF-8.
    ok = mysql:execute(Pid, Ins, [<<"blob">>, [16#161], 3.14, 3.14, 3.14,
                                  2014, {0, {0, 22, 11}}, 
                                  {{2014, 11, 03}, {0, 22, 24}},
                                  {2014, 11, 03}, null]),

    {ok, Stmt} = mysql:prepare(Pid, <<"SELECT * FROM t WHERE id=?">>),
    {ok, Columns, Rows} = mysql:execute(Pid, Stmt, [1]),
    ?assertEqual([<<"id">>, <<"bl">>, <<"tx">>, <<"f">>, <<"d">>, <<"dc">>,
                  <<"y">>, <<"ti">>,
                  <<"ts">>, <<"da">>, <<"c">>], Columns),
    ?assertEqual([[1, <<"blob">>, <<197, 161>>, 3.14, 3.14, 3.14,
                   2014, {0, {0, 22, 11}},
                   {{2014, 11, 03}, {00, 22, 24}}, {2014, 11, 03}, null]],
                 Rows),

    ok = mysql:query(Pid, <<"DROP TABLE t">>).

float_rounding(Pid) ->
    %% This is to make sure we get the same values for 32-bit FLOATs in the text
    %% and binary protocols for ordinary queries and prepared statements
    %% respectively.
    %%
    %% MySQL rounds to 6 significant digits when "printing" floats over the
    %% text protocol. When we receive a float on the binary protocol, we round
    %% it in the same way to match what MySQL does on the text protocol. This
    %% way we should to get the same values regardless of which protocol is
    %% used.

    %% Table for testing floats
    ok = mysql:query(Pid, "CREATE TABLE f (f FLOAT)"),

    %% Prepared statements
    {ok, Insert} = mysql:prepare(Pid, "INSERT INTO f (f) VALUES (?)"),
    {ok, Select} = mysql:prepare(Pid, "SELECT f FROM f"),

    %% [{Input, Expected}]
    TestData = [{1.0, 1.0}, {0.0, 0.0}, {3.14, 3.14}, {0.2, 0.2},
                {0.20082111, 0.200821}, {0.000123456789, 0.000123457},
                {33.3333333, 33.3333}, {-33.2233443322, -33.2233},
                {400.0123, 400.012}, {1000.1234, 1000.12},
                {999.00009, 999.0},
                {1234.5678, 1234.57}, {68888.8888, 68888.9},
                {123456.789, 123457.0}, {7654321.0, 7654320.0},
                {80001111.1, 80001100.0}, {987654321.0, 987654000.0},
                {-123456789.0, -123457000.0},
                {2.12345111e-23, 2.12345e-23}, {-2.12345111e-23, -2.12345e-23},
                {2.12345111e23, 2.12345e23}, {-2.12345111e23, -2.12345e23}],
    lists:foreach(fun ({Input, Expected}) ->
                      %% Insert using binary protocol (sending it as a double)
                      ok = mysql:execute(Pid, Insert, [Input]),

                      %% Text (plain query)
                      {ok, _, [[Value]]} = mysql:query(Pid, "SELECT f FROM f"),
                      ?assertEqual(Expected, Value),

                      %% Binary (prepared statement)
                      {ok, _, [[BinValue]]} = mysql:execute(Pid, Select, []),
                      ?assertEqual(Expected, BinValue),

                      %% cleanup before the next test
                      ok = mysql:query(Pid, "DELETE FROM f")
                end,
                TestData),
    ok = mysql:query(Pid, "DROP TABLE f").

decimal(Pid) ->
    %% As integer when S == 0
    ok = mysql:query(Pid, "CREATE TABLE dec0 (d DECIMAL(50, 0))"),
    write_read_text_binary(
        Pid, 14159265358979323846264338327950288419716939937510,
        <<"14159265358979323846264338327950288419716939937510">>,
        <<"dec0">>, <<"d">>
    ),
    write_read_text_binary(
        Pid, -14159265358979323846264338327950288419716939937510,
        <<"-14159265358979323846264338327950288419716939937510">>,
        <<"dec0">>, <<"d">>
    ),
    ok = mysql:query(Pid, "DROP TABLE dec0"),
    %% As float when P =< 15, S > 0
    ok = mysql:query(Pid, "CREATE TABLE dec15 (d DECIMAL(15, 14))"),
    write_read_text_binary(Pid, 3.14159265358979, <<"3.14159265358979">>,
                           <<"dec15">>, <<"d">>),
    write_read_text_binary(Pid, -3.14159265358979, <<"-3.14159265358979">>,
                           <<"dec15">>, <<"d">>),
    write_read_text_binary(Pid, 3.0, <<"3">>, <<"dec15">>, <<"d">>),
    ok = mysql:query(Pid, "DROP TABLE dec15"),
    %% As binary when P >= 16, S > 0
    ok = mysql:query(Pid, "CREATE TABLE dec16 (d DECIMAL(16, 15))"),
    write_read_text_binary(Pid, <<"3.141592653589793">>,
                           <<"3.141592653589793">>, <<"dec16">>, <<"d">>),
    write_read_text_binary(Pid, <<"-3.141592653589793">>,
                           <<"-3.141592653589793">>, <<"dec16">>, <<"d">>),
    write_read_text_binary(Pid, <<"3.000000000000000">>, <<"3">>,
                           <<"dec16">>, <<"d">>),
    ok = mysql:query(Pid, "DROP TABLE dec16").

int(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE ints (i INT)"),
    write_read_text_binary(Pid, 42, <<"42">>, <<"ints">>, <<"i">>),
    write_read_text_binary(Pid, -42, <<"-42">>, <<"ints">>, <<"i">>),
    write_read_text_binary(Pid, 987654321, <<"987654321">>, <<"ints">>,
                           <<"i">>),
    write_read_text_binary(Pid, -987654321, <<"-987654321">>,
                           <<"ints">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE ints"),
    %% Overflow with TINYINT
    ok = mysql:query(Pid, "CREATE TABLE tint (i TINYINT)"),
    write_read_text_binary(Pid, 127, <<"1000">>, <<"tint">>, <<"i">>),
    write_read_text_binary(Pid, -128, <<"-1000">>, <<"tint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE tint"),
    %% SMALLINT
    ok = mysql:query(Pid, "CREATE TABLE sint (i SMALLINT)"),
    write_read_text_binary(Pid, 32000, <<"32000">>, <<"sint">>, <<"i">>),
    write_read_text_binary(Pid, -32000, <<"-32000">>, <<"sint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE sint"),
    %% BIGINT
    ok = mysql:query(Pid, "CREATE TABLE bint (i BIGINT)"),
    write_read_text_binary(Pid, 123456789012, <<"123456789012">>,
                           <<"bint">>, <<"i">>),
    write_read_text_binary(Pid, -123456789012, <<"-123456789012">>,
                           <<"bint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE bint").

%% The BIT(N) datatype in MySQL 5.0.3 and later: the equivallent to bitstring()
bit(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE bits (b BIT(11))"),
    write_read_text_binary(Pid, <<16#ff, 0:3>>, <<"b'11111111000'">>,
                           <<"bits">>, <<"b">>),
    write_read_text_binary(Pid, <<16#7f, 6:3>>, <<"b'01111111110'">>,
                           <<"bits">>, <<"b">>),
    ok = mysql:query(Pid, "DROP TABLE bits").

date(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE d (d DATE)"),
    lists:foreach(
        fun ({Value, SqlLiteral}) ->
            write_read_text_binary(Pid, Value, SqlLiteral, <<"d">>, <<"d">>)
        end,
        [{{2014, 11, 03}, <<"'2014-11-03'">>},
         {{0, 0, 0},      <<"'0000-00-00'">>}]
    ),
    ok = mysql:query(Pid, "DROP TABLE d").

%% Test TIME value representation. There are a few things to check.
time(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE tm (tm TIME)"),
    lists:foreach(
        fun ({Value, SqlLiteral}) ->
            write_read_text_binary(Pid, Value, SqlLiteral, <<"tm">>, <<"tm">>)
        end,
        [{{0, {10, 11, 12}},   <<"'10:11:12'">>},
         {{5, {0, 0, 1}},     <<"'120:00:01'">>},
         {{-1, {23, 59, 59}}, <<"'-00:00:01'">>},
         {{-1, {23, 59, 0}},  <<"'-00:01:00'">>},
         {{-1, {23, 0, 0}},   <<"'-01:00:00'">>},
         {{-1, {0, 0, 0}},    <<"'-24:00:00'">>},
         {{-5, {10, 0, 0}},  <<"'-110:00:00'">>},
         {{0, {0, 0, 0}},      <<"'00:00:00'">>}]
    ),
    %% Zero seconds as a float.
    ok = mysql:query(Pid, "INSERT INTO tm (tm) VALUES (?)",
                     [{-1, {1, 2, 0.0}}]),
    ?assertEqual({ok, [<<"tm">>], [[{-1, {1, 2, 0}}]]},
                 mysql:query(Pid, "SELECT tm FROM tm")),
    ok = mysql:query(Pid, "DROP TABLE tm").

datetime(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE dt (dt DATETIME)"),
    lists:foreach(
        fun ({Value, SqlLiteral}) ->
            write_read_text_binary(Pid, Value, SqlLiteral, <<"dt">>, <<"dt">>)
        end,
        [{{{2014, 12, 14}, {19, 39, 20}},   <<"'2014-12-14 19:39:20'">>},
         {{{2014, 12, 14}, {0, 0, 0}},      <<"'2014-12-14 00:00:00'">>},
         {{{0, 0, 0}, {0, 0, 0}},           <<"'0000-00-00 00:00:00'">>}]
    ),
    ok = mysql:query(Pid, "DROP TABLE dt").

microseconds(Pid) ->
    %% Check whether we have the required version for this testcase.
    {ok, _, [[Version]]} = mysql:query(Pid, <<"SELECT @@version">>),
    try
        %% Remove stuff after dash for e.g. "5.5.40-0ubuntu0.12.04.1-log"
        [Version1 | _] = binary:split(Version, <<"-">>),
        Version2 = lists:map(fun binary_to_integer/1,
                             binary:split(Version1, <<".">>, [global])),
        Version2 >= [5, 6, 4] orelse throw(nope)
    of _ ->
        test_time_microseconds(Pid),
        test_datetime_microseconds(Pid)
    catch _:_ ->
        error_logger:info_msg("Skipping microseconds test. Current MySQL"
                              " version is ~s. Required version is >= 5.6.4.~n",
                              [Version])
    end.

test_time_microseconds(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE m (t TIME(6))"),
    %% Positive time
    write_read_text_binary(Pid, {0, {23, 59, 57.654321}},
                           <<"'23:59:57.654321'">>, <<"m">>, <<"t">>),
    %% Negative time
    write_read_text_binary(Pid, {-1, {23, 59, 57.654321}},
                           <<"'-00:00:02.345679'">>, <<"m">>, <<"t">>),
    ok = mysql:query(Pid, "DROP TABLE m").

test_datetime_microseconds(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE dt (dt DATETIME(6))"),
    write_read_text_binary(Pid, {{2014, 11, 23}, {23, 59, 57.654321}},
                           <<"'2014-11-23 23:59:57.654321'">>, <<"dt">>,
                           <<"dt">>),
    ok = mysql:query(Pid, "DROP TABLE dt").

%% @doc Tests write and read in text and the binary protocol, all combinations.
%% This helper function assumes an empty table with a single column.
write_read_text_binary(Conn, Term, SqlLiteral, Table, Column) ->
    SelectQuery = <<"SELECT ", Column/binary, " FROM ", Table/binary>>,
    {ok, SelectStmt} = mysql:prepare(Conn, SelectQuery),

    %% Insert as text, read text and binary, delete
    InsertQuery = <<"INSERT INTO ", Table/binary, " (", Column/binary, ")"
                    " VALUES (", SqlLiteral/binary, ")">>,
    ok = mysql:query(Conn, InsertQuery),
    ?assertEqual({ok, [Column], [[Term]]}, mysql:query(Conn, SelectQuery)),
    ?assertEqual({ok, [Column], [[Term]]}, mysql:execute(Conn, SelectStmt, [])),
    mysql:query(Conn, <<"DELETE FROM ", Table/binary>>),

    %% Insert as binary, read text and binary, delete
    InsertQ = <<"INSERT INTO ", Table/binary, " (", Column/binary, ")",
                " VALUES (?)">>,
    {ok, InsertStmt} = mysql:prepare(Conn, InsertQ),
    ok = mysql:execute(Conn, InsertStmt, [Term]),
    ok = mysql:unprepare(Conn, InsertStmt),
    ?assertEqual({ok, [Column], [[Term]]}, mysql:query(Conn, SelectQuery)),
    ?assertEqual({ok, [Column], [[Term]]}, mysql:execute(Conn, SelectStmt, [])),
    mysql:query(Conn, <<"DELETE FROM ", Table/binary>>),

    %% Cleanup
    ok = mysql:unprepare(Conn, SelectStmt).

%% --------------------------------------------------------------------------

timeout_test_() ->
    {setup,
     fun () ->
         {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                       {log_warnings, false}]),
         Pid
     end,
     fun (Pid) ->
         exit(Pid, normal)
     end,
     {with, [fun (Pid) ->
                 %% SLEEP was added in MySQL 5.0.12
                 ?assertEqual({ok, [<<"SLEEP(5)">>], [[1]]},
                              mysql:query(Pid, <<"SELECT SLEEP(5)">>, 40)),

                 %% A query after an interrupted query shouldn't get a timeout.
                 ?assertMatch({ok,[<<"42">>], [[42]]},
                              mysql:query(Pid, <<"SELECT 42">>)),

                 %% Parametrized query
                 ?assertEqual({ok, [<<"SLEEP(?)">>], [[1]]},
                              mysql:query(Pid, <<"SELECT SLEEP(?)">>, [5], 40)),

                 %% Prepared statement
                 {ok, Stmt} = mysql:prepare(Pid, <<"SELECT SLEEP(?)">>),
                 ?assertEqual({ok, [<<"SLEEP(?)">>], [[1]]},
                              mysql:execute(Pid, Stmt, [5], 40)),
                 ok = mysql:unprepare(Pid, Stmt)
             end]}}.

%% --------------------------------------------------------------------------

%% Prepared statements

with_table_foo_test_() ->
    {setup,
     fun () ->
         {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                       {query_cache_time, 50},
                                       {log_warnings, false}]),
         ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
         ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
         ok = mysql:query(Pid, <<"USE otptest">>),
         ok = mysql:query(Pid, <<"CREATE TABLE foo (bar INT) engine=InnoDB">>),
         Pid
     end,
     fun (Pid) ->
         ok = mysql:query(Pid, <<"DROP DATABASE otptest">>),
         exit(Pid, normal)
     end,
     fun (Pid) ->
         [{"Prepared statements", fun () -> prepared_statements(Pid) end},
          {"Parametrized queries", fun () -> parameterized_query(Pid) end}]
     end}.

prepared_statements(Pid) ->
    %% Unnamed
    ?assertEqual({error,{1146, <<"42S02">>,
                         <<"Table 'otptest.tab' doesn't exist">>}},
                 mysql:prepare(Pid, "SELECT * FROM tab WHERE id = ?")),
    {ok, StmtId} = mysql:prepare(Pid, "SELECT * FROM foo WHERE bar = ?"),
    ?assert(is_integer(StmtId)),
    ?assertEqual(ok, mysql:unprepare(Pid, StmtId)),
    ?assertEqual({error, not_prepared}, mysql:unprepare(Pid, StmtId)),

    %% Named
    ?assertEqual({error,{1146, <<"42S02">>,
                         <<"Table 'otptest.tab' doesn't exist">>}},
                 mysql:prepare(Pid, tab, "SELECT * FROM tab WHERE id = ?")),
    ?assertEqual({ok, foo},
                 mysql:prepare(Pid, foo, "SELECT * FROM foo WHERE bar = ?")),
    %% Prepare again unprepares the old stmt associated with this name.
    ?assertEqual({ok, foo},
                 mysql:prepare(Pid, foo, "SELECT bar FROM foo WHERE bar = ?")),
    ?assertEqual(ok, mysql:unprepare(Pid, foo)),
    ?assertEqual({error, not_prepared}, mysql:unprepare(Pid, foo)),

    %% Execute when not prepared
    ?assertEqual({error, not_prepared}, mysql:execute(Pid, not_a_stmt, [])),
    ok.

parameterized_query(Conn) ->
    %% To see that cache eviction works as expected, look at the code coverage.
    {ok, _, []} = mysql:query(Conn, "SELECT * FROM foo WHERE bar = ?", [1]),
    {ok, _, []} = mysql:query(Conn, "SELECT * FROM foo WHERE bar = ?", [2]),
    receive after 150 -> ok end, %% Now the query cache should emptied
    {ok, _, []} = mysql:query(Conn, "SELECT * FROM foo WHERE bar = ?", [3]),
    {error, {_, _, _}} = mysql:query(Conn, "Lorem ipsum dolor sit amet", [x]).

%% --- simple gen_server callbacks ---

gen_server_coverage_test() ->
    %%{noreply, state} = mysql:handle_cast(foo, state),
    %%{noreply, state} = mysql:handle_info(foo, state),
    %%ok = mysql:terminate(kill, state).
    ok.

