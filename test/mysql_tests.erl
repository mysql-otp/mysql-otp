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
                          "  dc DECIMAL(5,3),"
                          "  ti TIME,"
                          "  ts TIMESTAMP,"
                          "  da DATE,"
                          "  c CHAR(2)"
                          ") ENGINE=InnoDB">>).

connect_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password}]),
    exit(Pid, normal).

query_test_() ->
    {setup,
     fun () ->
         {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password}]),
         ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
         ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
         ok = mysql:query(Pid, <<"USE otptest">>),
         Pid
     end,
     fun (Pid) ->
         ok = mysql:query(Pid, <<"DROP DATABASE otptest">>),
         exit(Pid, normal)
     end,
     {with, [fun basic_queries/1,
             fun text_protocol/1,
             fun binary_protocol/1,
             fun float_rounding/1,
             fun time/1,
             fun microseconds/1]}}.

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

text_protocol(Pid) ->
    ok = mysql:query(Pid, ?create_table_t),
    ok = mysql:query(Pid, <<"INSERT INTO t (bl, f, dc, ti, ts, da, c)"
                            " VALUES ('blob', 3.14, 3.14, '00:22:11',"
                            " '2014-11-03 00:22:24', '2014-11-03',"
                            " NULL)">>),
    ?assertEqual(1, mysql:warning_count(Pid)), %% tx has no default value
    ?assertEqual(1, mysql:insert_id(Pid)),     %% auto_increment starts from 1
    ?assertEqual(1, mysql:affected_rows(Pid)),

    %% select
    {ok, Columns, Rows} = mysql:query(Pid, <<"SELECT * FROM t">>),
    ?assertEqual([<<"id">>, <<"bl">>, <<"tx">>, <<"f">>, <<"dc">>, <<"ti">>,
                  <<"ts">>, <<"da">>, <<"c">>], Columns),
    ?assertEqual([[1, <<"blob">>, <<>>, 3.14, <<"3.140">>, {0, {0, 22, 11}},
                   {{2014, 11, 03}, {00, 22, 24}}, {2014, 11, 03}, null]],
                 Rows),

    %% TODO:
    %% * More types: BIT, SET, ENUM, GEOMETRY
    %% * TIME with negative hours
    %% * TIME with more than 2 digits in hour.
    %% * TIME with microseconds
    %% * Negative TIME

    ok = mysql:query(Pid, <<"DROP TABLE t">>).

binary_protocol(Pid) ->
    ok = mysql:query(Pid, ?create_table_t),
    %% The same queries as in the text protocol. Expect the same results.
    {ok, Ins} = mysql:prepare(Pid, <<"INSERT INTO t (bl, f, dc, ti, ts, da, c)"
                                     " VALUES (?, ?, ?, ?, ?, ?, ?)">>),

    ok = mysql:execute(Pid, Ins, [<<"blob">>, 3.14, <<"3.14">>,
                                  {0, {0, 22, 11}}, 
                                  {{2014, 11, 03}, {0, 22, 24}},
                                  {2014, 11, 03}, null]),

    %% TODO: Put the expected result in a macro to make sure they are identical
    %% for the text and the binary protocol tests.

    {ok, Stmt} = mysql:prepare(Pid, <<"SELECT * FROM t WHERE id=?">>),
    {ok, Columns, Rows} = mysql:execute(Pid, Stmt, [1]),
    ?assertEqual([<<"id">>, <<"bl">>, <<"tx">>, <<"f">>, <<"dc">>, <<"ti">>,
                  <<"ts">>, <<"da">>, <<"c">>], Columns),
    ?assertEqual([[1, <<"blob">>, <<>>, 3.14, <<"3.140">>,
                   {0, {0, 22, 11}},
                   {{2014, 11, 03}, {00, 22, 24}}, {2014, 11, 03}, null]],
                 Rows),

    %% TODO: Both send and receive the following values:
    %% * Values for all types
    %% * Negative numbers for all integer types
    %% * Integer overflow
    %% * TIME with more than 2 digits in hour.
    %% * TIME with microseconds
    %% * Negative TIME

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
    TestData = [{1.0, 1.0}, {3.14, 3.14}, {0.2, 0.2},
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

%% Test TIME value representation. There are a few things to check.
time(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE tm (tm TIME)"),
    {ok, Insert} = mysql:prepare(Pid, "INSERT INTO tm VALUES (?)"),
    {ok, Select} = mysql:prepare(Pid, "SELECT tm FROM tm"),
    lists:foreach(
        fun ({Value, Text}) ->
            %% --- Insert using text query ---
            ok = mysql:query(Pid, ["INSERT INTO tm VALUES ('", Text, "')"]),
            %% Select using prepared statement
            ?assertEqual({ok, [<<"tm">>], [[Value]]},
                         mysql:execute(Pid, Select, [])),
            %% Select using plain query
            ?assertEqual({ok, [<<"tm">>], [[Value]]},
                         mysql:query(Pid, "SELECT tm FROM tm")),
            %% Empty table
            ok = mysql:query(Pid, "DELETE FROM tm"),
            %% --- Insert using prepared statement ---
            ok = mysql:execute(Pid, Insert, [Value]),
            %% Select using prepared statement
            ?assertEqual({ok, [<<"tm">>], [[Value]]},
                         mysql:execute(Pid, Select, [])),
            %% Select using plain query
            ?assertEqual({ok, [<<"tm">>], [[Value]]},
                         mysql:query(Pid, "SELECT tm FROM tm")),
            %% Empty table
            ok = mysql:query(Pid, "DELETE FROM tm"),
            ok
        end,
        [{{0, {10, 11, 12}},   "10:11:12"},
         {{5, {0, 0, 1}},     "120:00:01"},
         {{-1, {23, 59, 59}}, "-00:00:01"},
         {{-1, {23, 59, 0}},  "-00:01:00"},
         {{-1, {23, 0, 0}},   "-01:00:00"},
         {{-1, {0, 0, 0}},    "-24:00:00"},
         {{-5, {10, 0, 0}},  "-110:00:00"}]
    ),
    ok = mysql:query(Pid, "DROP TABLE tm").

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
        run_test_microseconds(Pid)
    catch _:_ ->
        error_logger:info_msg("Skipping microseconds test. Current MySQL"
                              " version is ~s. Required version is >= 5.6.4.~n",
                              [Version])
    end.

run_test_microseconds(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE m (t TIME(6))"),
    SelectTime = "SELECT t FROM m",
    {ok, SelectStmt} = mysql:prepare(Pid, SelectTime),
    {ok, InsertStmt} = mysql:prepare(Pid, "INSERT INTO m VALUES (?)"),
    %% Positive time, insert using plain query
    E1 = {0, {23, 59, 57.654321}},
    ok = mysql:query(Pid, <<"INSERT INTO m VALUES ('23:59:57.654321')">>),
    ?assertEqual({ok, [<<"t">>], [[E1]]}, mysql:query(Pid, SelectTime)),
    ?assertEqual({ok, [<<"t">>], [[E1]]}, mysql:execute(Pid, SelectStmt, [])),
    ok = mysql:query(Pid, "DELETE FROM m"),
    %% The same, but insert using prepared stmt
    ok = mysql:execute(Pid, InsertStmt, [E1]),
    ?assertEqual({ok, [<<"t">>], [[E1]]}, mysql:query(Pid, SelectTime)),
    ?assertEqual({ok, [<<"t">>], [[E1]]}, mysql:execute(Pid, SelectStmt, [])),
    ok = mysql:query(Pid, "DELETE FROM m"),
    %% Negative time
    E2 = {-1, {23, 59, 57.654321}},
    ok = mysql:query(Pid, <<"INSERT INTO m VALUES ('-00:00:02.345679')">>),
    ?assertEqual({ok, [<<"t">>], [[E2]]}, mysql:query(Pid, SelectTime)),
    ?assertEqual({ok, [<<"t">>], [[E2]]}, mysql:execute(Pid, SelectStmt, [])),
    ok = mysql:query(Pid, "DELETE FROM m"),
    %% The same, but insert using prepared stmt
    ok = mysql:execute(Pid, InsertStmt, [E2]),
    ?assertEqual({ok, [<<"t">>], [[E2]]}, mysql:query(Pid, SelectTime)),
    ?assertEqual({ok, [<<"t">>], [[E2]]}, mysql:execute(Pid, SelectStmt, [])),
    ok = mysql:query(Pid, "DROP TABLE m"),
    %% Datetime
    Q3 = <<"SELECT TIMESTAMP '2014-11-23 23:59:57.654321' AS t">>,
    E3 = [[{{2014, 11, 23}, {23, 59, 57.654321}}]],
    ?assertEqual({ok, [<<"t">>], E3}, mysql:query(Pid, Q3)),
    {ok, S3} = mysql:prepare(Pid, Q3),
    ?assertEqual({ok, [<<"t">>], E3}, mysql:execute(Pid, S3, [])),
    ok.

