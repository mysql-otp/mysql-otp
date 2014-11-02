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
