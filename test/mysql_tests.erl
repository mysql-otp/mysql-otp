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

connect_test() ->
    {ok, Pid} = mysql:connect([{user, ?user}, {password, ?password}]),

    %% A query without a result set
    ?assertEqual(ok, mysql:query(Pid, <<"USE otptest">>)),

    ?assertEqual(ok, mysql:disconnect(Pid)).

query_test_() ->
    {setup,
     fun () ->
         {ok, Pid} = mysql:connect([{user, ?user}, {password, ?password}]),
         %ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
         %ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
         ok = mysql:query(Pid, <<"USE otptest">>),
         Pid
     end,
     fun (Pid) ->
         mysql:disconnect(Pid)
     end,
     {with, [fun basic_queries/1]}}.

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

    %{ok, Fields, Rows} = mysql:query(Pid, <<"SELECT * FROM settest">>),
    ok.
