%% MySQL/OTP – a MySQL driver for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
%%
%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU General Public License as published by
%% the Free Software Foundation, either version 3 of the License, or
%% (at your option) any later version.
%%
%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
%% GNU General Public License for more details.
%%
%% You should have received a copy of the GNU General Public License
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
    {ok, Pid} = mysql:connect([{user, ?user}, {password, ?password}]),
    ?assertEqual(ok, mysql:disconnect(Pid)).

query_test_() ->
    {setup,
     fun () ->
         {ok, Pid} = mysql:connect([{user, ?user}, {password, ?password}]),
         ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
         ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
         ok = mysql:query(Pid, <<"USE otptest">>),
         Pid
     end,
     fun (Pid) ->
         ok = mysql:query(Pid, <<"DROP DATABASE otptest">>),
         mysql:disconnect(Pid)
     end,
     {with, [fun basic_queries/1,
             fun text_protocol/1,
             fun binary_protocol/1]}}.

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
    ?assertEqual([[1, <<"blob">>, <<>>, 3.14, <<"3.140">>, {time, {0, 22, 11}},
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

    ok = mysql:query(Pid, Ins, [<<"blob">>, 3.14, <<"3.14">>,
                                {time, {0, 22, 11}}, 
                                {{2014, 11, 03}, {0, 22, 24}},
                                {2014, 11, 03}, null]),

    %% TODO: Put the expected result in a macro to make sure they are identical
    %% for the text and the binary protocol tests.

    %% One thing that are not identical in the text and binary protocols are
    %% floats. We get the float as a 32-bit float, so the value is not exactly
    %% what we inserted.
    <<ExpectedFloat:32/native-float>> = <<3.14:32/native-float>>,

    {ok, Stmt} = mysql:prepare(Pid, <<"SELECT * FROM t WHERE id=?">>),
    {ok, Columns, Rows} = mysql:query(Pid, Stmt, [1]),
    ?assertEqual([<<"id">>, <<"bl">>, <<"tx">>, <<"f">>, <<"dc">>, <<"ti">>,
                  <<"ts">>, <<"da">>, <<"c">>], Columns),
    ?assertEqual([[1, <<"blob">>, <<>>, ExpectedFloat, <<"3.140">>,
                   {time, {0, 22, 11}},
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
