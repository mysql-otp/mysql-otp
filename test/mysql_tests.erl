%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014-2016 Viktor Söderqvist
%%               2017 Piotr Nosek
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

-define(user,         "otptest").
-define(password,     "otptest").
-define(ssl_user,     "otptestssl").
-define(ssl_password, "otptestssl").

%% We need to set a the SQL mode so it is consistent across MySQL versions
%% and distributions.
-define(SQL_MODE, <<"NO_ENGINE_SUBSTITUTION">>).

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

connect_synchronous_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {connect_mode, synchronous}]),
    ?assert(mysql:is_connected(Pid)),
    mysql:stop(Pid),
    ok.

connect_asynchronous_successful_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {connect_mode, asynchronous}]),
    ?assert(mysql:is_connected(Pid)),
    mysql:stop(Pid),
    ok.

connect_asynchronous_failing_test() ->
    process_flag(trap_exit, true),
    {ok, Ret, _Logged} = error_logger_acc:capture(
        fun () ->
            {ok, Pid} = mysql:start_link([{user, "dummy"}, {password, "junk"},
                                          {connect_mode, asynchronous}]),
            receive
                {'EXIT', Pid, {error, Error}} ->
                    true = is_access_denied(Error),
                    ok
            after 1000 ->
                error(no_exit_message)
            end
        end
    ),
    ?assertEqual(ok, Ret),
    process_flag(trap_exit, false),
    ok.

connect_lazy_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {connect_mode, lazy}]),
    ?assertNot(mysql:is_connected(Pid)),
    {ok, [<<"1">>], [[1]]} = mysql:query(Pid, <<"SELECT 1">>),
    ?assert(mysql:is_connected(Pid)),
    mysql:stop(Pid),
    ok.

failing_connect_test() ->
    process_flag(trap_exit, true),
    {ok, Ret, Logged} = error_logger_acc:capture(
        fun () ->
            mysql:start_link([{user, "dummy"}, {password, "junk"}])
        end),
    ?assertMatch([_|_], Logged), % some errors logged
    {error, Error} = Ret,
    true = is_access_denied(Error),
    receive
        {'EXIT', _Pid, Error} -> ok
    after 1000 ->
        error(no_exit_message)
    end,
    process_flag(trap_exit, false).

successful_connect_test() ->
    %% A connection with a registered name and execute initial queries and
    %% create prepared statements.
    Pid = common_basic_check([{user, ?user}, {password, ?password}]),

    %% Test some gen_server callbacks not tested elsewhere
    State = get_state(Pid),
    ?assertMatch({ok, State}, mysql_conn:code_change("0.1.0", State, [])),
    ?assertMatch({error, _}, mysql_conn:code_change("2.0.0", unknown_state, [])),
    common_conn_close().

common_basic_check(ExtraOpts) ->
    Options = [{name, {local, tardis}},
               {queries, ["SET @foo = 'bar'", "SELECT 1",
                          "SELECT 1; SELECT 2"]},
               {prepare, [{foo, "SELECT @foo"}]} | ExtraOpts],
    {ok, Pid} = mysql:start_link(Options),
    %% Check that queries and prepare has been done.
    ?assertEqual({ok, [<<"@foo">>], [[<<"bar">>]]},
                 mysql:execute(Pid, foo, [])),
    Pid.

common_conn_close() ->
    Pid = whereis(tardis),
    process_flag(trap_exit, true),
    mysql:stop(Pid),
    receive
        {'EXIT', Pid, normal} -> ok
    after
        5000 -> error({cant_stop_connection, Pid})
    end,
    process_flag(trap_exit, false).

exit_normal_test() ->
    Options = [{user, ?user}, {password, ?password}],
    {ok, Pid} = mysql:start_link(Options),
    {ok, ok, LoggedErrors} = error_logger_acc:capture(fun () ->
        %% Stop the connection without noise, errors or messages
        mysql:stop(Pid),
        receive
            UnexpectedExitMessage -> UnexpectedExitMessage
        after 0 ->
            ok
        end
    end),
    %% Check that we got nothing in the error log.
    ?assertEqual([], LoggedErrors).

server_disconnect_test() ->
    process_flag(trap_exit, true),
    Options = [{user, ?user}, {password, ?password}],
    {ok, Pid} = mysql:start_link(Options),
    {ok, ok, _LoggedErrors} = error_logger_acc:capture(fun () ->
        %% Make the server close the connection after 1 second of inactivity.
        ok = mysql:query(Pid, <<"SET SESSION wait_timeout = 1">>),
        receive
            {'EXIT', Pid, normal} -> ok
        after 2000 ->
            no_exit_message
        end
    end),
    process_flag(trap_exit, false),
    ?assertExit(noproc, mysql:stop(Pid)).

tcp_error_test() ->
    process_flag(trap_exit, true),
    Options = [{user, ?user}, {password, ?password}],
    {ok, Pid} = mysql:start_link(Options),
    {ok, ok, LoggedErrors} = error_logger_acc:capture(fun () ->
        %% Simulate a tcp error by sending a message. (Is there a better way?)
        Pid ! {tcp_error, dummy_socket, tcp_reason},
        receive
            {'EXIT', Pid, {tcp_error, tcp_reason}} -> ok
        after 1000 ->
            error(no_exit_message)
        end
    end),
    process_flag(trap_exit, false),
    %% Check that we got the expected crash report in the error log.
    [{error, Msg1}, {error, Msg2}, {error_report, CrashReport}] = LoggedErrors,
    %% "Connection Id 24 closing with reason: tcp_closed"
    ?assert(lists:prefix("Connection Id", Msg1)),
    ExpectedPrefix = io_lib:format("** Generic server ~p terminating", [Pid]),
    ?assert(lists:prefix(lists:flatten(ExpectedPrefix), Msg2)),
    ?assertMatch({crash_report, _}, CrashReport).

keep_alive_test() ->
     %% Let the connection send a few pings.
     process_flag(trap_exit, true),
     Options = [{user, ?user}, {password, ?password}, {keep_alive, 20}],
     {ok, Pid} = mysql:start_link(Options),
     receive after 70 -> ok end,
     State = get_state(Pid),
     [state, _Version, _ConnectionId, Socket | _] = tuple_to_list(State),
     {ok, ExitMessage, _LoggedErrors} = error_logger_acc:capture(fun () ->
         gen_tcp:close(Socket),
         receive
            Message -> Message
         after 1000 ->
             ping_didnt_crash_connection
         end
     end),
     process_flag(trap_exit, false),
     ?assertMatch({'EXIT', Pid, _Reason}, ExitMessage),
     ?assertExit(noproc, mysql:stop(Pid)).

reset_connection_test() ->
    %% Ignored test with MySQL earlier than 5.7
    Options = [{user, ?user}, {password, ?password}, {keep_alive, true}],
    {ok, Pid} = mysql:start_link(Options),
    ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
    ok = mysql:query(Pid, <<"USE otptest">>),
    ok = mysql:query(Pid, <<"SET autocommit = 1">>),
    ok = mysql:query(Pid, ?create_table_t),
    ok = mysql:query(Pid, <<"INSERT INTO t (id, tx) VALUES (1, 'text 1')">>),
    ?assertEqual(1, mysql:insert_id(Pid)),  %% auto_increment starts from 1
    case mysql:reset_connection(Pid) of
      ok ->
        ?assertEqual(0, mysql:insert_id(Pid)); %% insertid reset to 0;
      _Error ->
        ?assertEqual(1, mysql:insert_id(Pid)) %% reset failed
    end,
    mysql:stop(Pid),
    ok.

unix_socket_test() ->
    try
        list_to_integer(erlang:system_info(otp_release))
    of
        %% Supported in OTP >= 19
        OtpRelease when OtpRelease >= 19 ->
            %% Get socket file to use
            {ok, Pid1} = mysql:start_link([{user, ?user},
                                           {password, ?password}]),
            {ok, [<<"@@socket">>], [SockFile]} = mysql:query(Pid1,
                                                             "SELECT @@socket"),
            mysql:stop(Pid1),
            %% Connect through unix socket
            case mysql:start_link([{host, {local, SockFile}},
                                   {user, ?user}, {password, ?password}]) of
                {ok, Pid2} ->
                    ?assertEqual({ok, [<<"1">>], [[1]]},
                                 mysql:query(Pid2, <<"SELECT 1">>)),
                    mysql:stop(Pid2);
                {error, eafnosupport} ->
                    error_logger:info_msg("Skipping unix socket test. "
                                          "Not supported on this OS.~n")
            end;
        OtpRelease ->
            error_logger:info_msg("Skipping unix socket test. Current OTP "
                                  "release is ~B. Required release is >= 19.~n",
                                  [OtpRelease])
    catch
        error:badarg ->
            error_logger:info_msg("Skipping unix socket tests. Current OTP "
                                  "release could not be determined.~n")
    end.

connect_queries_failure_test() ->
    process_flag(trap_exit, true),
    {ok, Ret, Logged} = error_logger_acc:capture(
        fun () ->
            mysql:start_link([{user, ?user}, {password, ?password},
                              {queries, ["foo"]}])
        end),
    ?assertMatch([{error_report, {crash_report, _}}], Logged),
    {error, Reason} = Ret,
    receive
        {'EXIT', _Pid, Reason} -> ok
    after 1000 ->
        exit(no_exit_message)
    end,
    process_flag(trap_exit, false).

connect_prepare_failure_test() ->
    process_flag(trap_exit, true),
    {ok, Ret, Logged} = error_logger_acc:capture(
        fun () ->
            mysql:start_link([{user, ?user}, {password, ?password},
                                                {prepare, [{foo, "foo"}]}])
        end),
    ?assertMatch([{error_report, {crash_report, _}}], Logged),
    {error, Reason} = Ret,
    ?assertMatch({1064, <<"42000">>, <<"You have an erro", _/binary>>}, Reason),
    receive
        {'EXIT', _Pid, Reason} -> ok
    after 1000 ->
        exit(no_exit_message)
    end,
    process_flag(trap_exit, false).

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
         ok = mysql:query(Pid, <<"SET SESSION sql_mode = ?">>, [?SQL_MODE]),
         Pid
     end,
     fun (Pid) ->
         ok = mysql:query(Pid, <<"DROP DATABASE otptest">>),
         mysql:stop(Pid)
     end,
     fun (Pid) ->
         [{"Select db on connect",  fun () -> connect_with_db(Pid) end},
          {"Autocommit",            fun () -> autocommit(Pid) end},
          {"Encode",                fun () -> encode(Pid) end},
          {"Basic queries",         fun () -> basic_queries(Pid) end},
          {"Filtermap queries",     fun () -> filtermap_queries(Pid) end},
          {"FOUND_ROWS option",     fun () -> found_rows(Pid) end},
          {"Multi statements",      fun () -> multi_statements(Pid) end},
          {"Text protocol",         fun () -> text_protocol(Pid) end},
          {"Binary protocol",       fun () -> binary_protocol(Pid) end},
          {"FLOAT rounding",        fun () -> float_rounding(Pid) end},
          {"DECIMAL",               fun () -> decimal(Pid) end},
          {"DECIMAL truncated",     fun () -> decimal_trunc(Pid) end},
          {"Float as decimal",      fun () -> float_as_decimal(Pid) end},
          {"Float as decimal(2)",   fun () -> float_as_decimal_2(Pid) end},
          {"INT",                   fun () -> int(Pid) end},
          {"BIT(N)",                fun () -> bit(Pid) end},
          {"DATE",                  fun () -> date(Pid) end},
          {"TIME",                  fun () -> time(Pid) end},
          {"DATETIME",              fun () -> datetime(Pid) end},
          {"JSON",                  fun () -> json(Pid) end},
          {"Microseconds",          fun () -> microseconds(Pid) end},
          {"Invalid params",        fun () -> invalid_params(Pid) end}]
     end}.

local_files_test_() ->
    {setup,
     fun () ->
         {ok, Cwd0} = file:get_cwd(),
         Cwd1 = iolist_to_binary(Cwd0),
         Cwd2 = case binary:last(Cwd1) of
             $/ -> Cwd1;
             _ -> <<Cwd1/binary, $/>>
         end,
         {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                       {log_warnings, false},
                                       {keep_alive, true}, {allowed_local_paths, [Cwd2]}]),
         ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
         ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
         ok = mysql:query(Pid, <<"USE otptest">>),
         ok = mysql:query(Pid, <<"SET autocommit = 1">>),
         ok = mysql:query(Pid, <<"SET SESSION sql_mode = ?">>, [?SQL_MODE]),
         {Pid, Cwd2}
     end,
     fun ({Pid, _Cwd}) ->
         ok = mysql:query(Pid, <<"DROP DATABASE otptest">>),
         mysql:stop(Pid)
     end,
     fun ({Pid, Cwd}) ->
          [{"Single statement", fun () -> load_data_local_infile(Pid, Cwd) end},
          {"Missing file", fun () -> load_data_local_infile_missing(Pid, Cwd) end},
          {"Not allowed", fun () -> load_data_local_infile_not_allowed(Pid, Cwd) end},
          {"Multi statements", fun () -> load_data_local_infile_multi(Pid, Cwd) end}]
     end}.

connect_with_db(_Pid) ->
    %% Make another connection and set the db in the handshake phase
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {database, "otptest"}]),
    ?assertMatch({ok, _, [[<<"otptest">>]]},
                 mysql:query(Pid, "SELECT DATABASE()")),
    mysql:stop(Pid).

log_warnings_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password}]),
    ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
    ok = mysql:query(Pid, <<"USE otptest">>),
    ok = mysql:query(Pid, <<"SET SESSION sql_mode = ?">>, [?SQL_MODE]),
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
    mysql:stop(Pid).

log_slow_queries_test() ->
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {log_warnings, false}, {log_slow_queries, true}]),
    VersionStr = db_version_string(Pid),
    try
        Version = parse_db_version(VersionStr),
        case is_mariadb(VersionStr) of
            true when Version < [10, 0, 21] ->
                throw({mariadb, version_too_small});
            false when Version < [5, 5, 8] ->
                throw({mysql, version_too_small});
            _ ->
                ok
        end
    of _ ->
        ok = mysql:query(Pid, "SET long_query_time = 0.1"),

        %% single statement should not include query number
        SingleQuery = "SELECT SLEEP(0.2)",
        {ok, _, SingleLogged} = error_logger_acc:capture( fun () ->
            {ok, _, _} = mysql:query(Pid, SingleQuery)
        end),
        [{_, SingleLog}] = SingleLogged,
        ?assertEqual("MySQL query was slow: " ++ SingleQuery ++ "\n", SingleLog),

        %% multi statement should include number of slow query
        MultiQuery = "SELECT SLEEP(0.2); " %% #1 -> slow
                     "SELECT 1; "          %% #2 -> not slow
                     "SET @foo = 1; "      %% #3 -> not slow, no result set
                     "SELECT SLEEP(0.2); " %% #4 -> slow
                     "SELECT 1",           %% #5 -> not slow
        {ok, _, MultiLogged} = error_logger_acc:capture(fun () ->
            {ok, _} = mysql:query(Pid, MultiQuery)
        end),
        [{_, MultiLog1}, {_, MultiLog2}] = MultiLogged,
        ?assertEqual("MySQL query #1 was slow: " ++ MultiQuery ++ "\n", MultiLog1),
        ?assertEqual("MySQL query #4 was slow: " ++ MultiQuery ++ "\n", MultiLog2)
    catch
        throw:{mysql, version_too_small} ->
            error_logger:info_msg("Skipping Log Slow Queries test. Current MySQL version"
                                  " is ~s. Required version is >= 5.5.8.~n",
                                  [VersionStr]);
        throw:{mariadb, version_too_small} ->
            error_logger:info_msg("Skipping Log Slow Queries test. Current MariaDB version"
                                  " is ~s. Required version is >= 10.0.21.~n",
                                  [VersionStr])
    end,
    mysql:stop(Pid).

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

filtermap_queries(Pid) ->
    ok = mysql:query(Pid, ?create_table_t),
    ok = mysql:query(Pid, <<"INSERT INTO t (id, tx) VALUES (1, 'text 1')">>),
    ok = mysql:query(Pid, <<"INSERT INTO t (id, tx) VALUES (2, 'text 2')">>),
    ok = mysql:query(Pid, <<"INSERT INTO t (id, tx) VALUES (3, 'text 3')">>),

    Query = <<"SELECT id, tx FROM t ORDER BY id">>,

    %% one-ary filtermap fun
    FilterMap1 = fun
        ([1|_]) ->
            true;
        ([2|_]) ->
            false;
        (Row1=[3|_]) ->
            {true, list_to_tuple(Row1)}
    end,

    %% two-ary filtermap fun
    FilterMap2 = fun
        (_, Row2) ->
            FilterMap1(Row2)
    end,

    Expected = [[1, <<"text 1">>], {3, <<"text 3">>}],

    %% test with plain query
    {ok, _, Rows1}=mysql:query(Pid, Query, FilterMap1),
    ?assertEqual(Expected, Rows1),
    {ok, _, Rows2}=mysql:query(Pid, Query, FilterMap2),
    ?assertEqual(Expected, Rows2),

    %% test with parameterized query
    {ok, _, Rows3}=mysql:query(Pid, Query, [], FilterMap1),
    ?assertEqual(Expected, Rows3),
    {ok, _, Rows4}=mysql:query(Pid, Query, [], FilterMap2),
    ?assertEqual(Expected, Rows4),

    %% test with prepared statement
    {ok, PrepStmt} = mysql:prepare(Pid, Query),
    {ok, _, Rows5}=mysql:execute(Pid, PrepStmt, [], FilterMap1),
    ?assertEqual(Expected, Rows5),
    {ok, _, Rows6}=mysql:execute(Pid, PrepStmt, [], FilterMap2),
    ?assertEqual(Expected, Rows6),

    ok = mysql:query(Pid, <<"DROP TABLE t">>).

found_rows(Pid) ->
    Options = [{user, ?user}, {password, ?password}, {log_warnings, false},
               {keep_alive, true}, {found_rows, true}],
    {ok, FRPid} = mysql:start_link(Options),
    ok = mysql:query(FRPid, <<"USE otptest">>),

    ok = mysql:query(Pid, ?create_table_t),
    ok = mysql:query(Pid, <<"INSERT INTO t (id, tx) VALUES (1, 'text')">>),

    %% With no found_rows option, affected_rows for update returns 0
    ok = mysql:query(Pid, <<"UPDATE t SET tx = 'text' WHERE id = 1">>),
    ?assertEqual(0, mysql:affected_rows(Pid)),

    %% With found_rows, affected_rows returns the number of rows found
    ok = mysql:query(FRPid, <<"UPDATE t SET tx = 'text' WHERE id = 1">>),
    ?assertEqual(1, mysql:affected_rows(FRPid)),

    ok = mysql:query(Pid, <<"DROP TABLE t">>).


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

decimal_trunc(_Pid) ->
    %% Create another connection with log_warnings enabled.
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {log_warnings, true}]),
    ok = mysql:query(Pid, <<"USE otptest">>),
    ok = mysql:query(Pid, <<"SET autocommit = 1">>),
    ok = mysql:query(Pid, <<"SET SESSION sql_mode = ?">>, [?SQL_MODE]),
    ok = mysql:query(Pid, <<"CREATE TABLE `test_decimals` ("
                            "  `id` bigint(20) unsigned NOT NULL,"
                            "  `balance` decimal(13,4) NOT NULL,"
                            "  PRIMARY KEY (`id`)"
                            ") ENGINE=InnoDB;">>),
    ok = mysql:query(Pid, <<"INSERT INTO test_decimals (id, balance)"
                            " VALUES (1, 5000), (2, 5000), (3, 5000);">>),
    {ok, decr} = mysql:prepare(Pid, decr, <<"UPDATE test_decimals"
                                            " SET balance = balance - ?"
                                            " WHERE id = ?">>),
    %% Decimal sent as float gives truncation warning.
    {ok, ok, [{_, LoggedWarning1}|_]} = error_logger_acc:capture(fun () ->
        ok = mysql:execute(Pid, decr, [10.2, 1]),
        ok = mysql:execute(Pid, decr, [10.2, 1]),
        ok = mysql:execute(Pid, decr, [10.2, 1]),
        ok = mysql:execute(Pid, decr, [10.2, 1])
    end),
    ?assertMatch("Note 1265: Data truncated for column 'balance'" ++ _,
                 LoggedWarning1),
    %% Decimal sent as binary gives truncation warning.
    {ok, ok, [{_, LoggedWarning2}|_]} = error_logger_acc:capture(fun () ->
        ok = mysql:execute(Pid, decr, [<<"10.2">>, 2]),
        ok = mysql:execute(Pid, decr, [<<"10.2">>, 2]),
        ok = mysql:execute(Pid, decr, [<<"10.2">>, 2]),
        ok = mysql:execute(Pid, decr, [<<"10.2">>, 2])
    end),
    ?assertMatch("Note 1265: Data truncated for column 'balance'" ++ _,
                 LoggedWarning2),
    %% Decimal sent as DECIMAL => no warning
    {ok, ok, []} = error_logger_acc:capture(fun () ->
        ok = mysql:execute(Pid, decr, [{decimal, <<"10.2">>}, 3]),
        ok = mysql:execute(Pid, decr, [{decimal, "10.2"}, 3]),
        ok = mysql:execute(Pid, decr, [{decimal, 10.2}, 3]),
        ok = mysql:execute(Pid, decr, [{decimal, 10.2}, 3]),
        ok = mysql:execute(Pid, decr, [{decimal, 0}, 3]) % <- integer coverage
    end),
    ?assertMatch({ok, _, [[1, 4959.2], [2, 4959.2], [3, 4959.2]]},
                 mysql:query(Pid, <<"SELECT id, balance FROM test_decimals">>)),
    ok = mysql:query(Pid, "DROP TABLE test_decimals"),
    ok = mysql:stop(Pid).

float_as_decimal(_Pid) ->
    %% Create another connection with {float_as_decimal, true}
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {log_warnings, true},
                                  {float_as_decimal, true}]),
    ok = mysql:query(Pid, <<"USE otptest">>),
    ok = mysql:query(Pid, <<"SET autocommit = 1">>),
    ok = mysql:query(Pid, <<"SET SESSION sql_mode = ?">>, [?SQL_MODE]),
    ok = mysql:query(Pid, <<"CREATE TABLE float_as_decimal ("
                            "  balance decimal(13,4) NOT NULL"
                            ") ENGINE=InnoDB;">>),
    ok = mysql:query(Pid, <<"INSERT INTO float_as_decimal (balance)"
                            " VALUES (5000);">>),
    {ok, decr} = mysql:prepare(Pid, decr, <<"UPDATE float_as_decimal"
                                            " SET balance = balance - ?">>),
    %% Floats sent as decimal => no truncation warning.
    {ok, ok, []} = error_logger_acc:capture(fun () ->
        ok = mysql:execute(Pid, decr, [10.2]),
        ok = mysql:execute(Pid, decr, [10.2]),
        ok = mysql:execute(Pid, decr, [10.2]),
        ok = mysql:execute(Pid, decr, [10.2])
    end),
    ok = mysql:query(Pid, "DROP TABLE float_as_decimal;"),
    ok = mysql:stop(Pid).

float_as_decimal_2(_Pid) ->
    %% Create another connection with {float_as_decimal, 2}.
    %% Check that floats are sent as DECIMAL with 2 decimals.
    {ok, Pid} = mysql:start_link([{user, ?user}, {password, ?password},
                                  {log_warnings, true},
                                  {float_as_decimal, 2}]),
    ok = mysql:query(Pid, <<"USE otptest">>),
    ok = mysql:query(Pid, <<"SET autocommit = 1">>),
    ok = mysql:query(Pid, <<"SET SESSION sql_mode = ?">>, [?SQL_MODE]),
    ok = mysql:query(Pid, <<"CREATE TABLE dec13_4 (d DECIMAL(13,4))">>),
    ok = mysql:query(Pid, <<"INSERT INTO dec13_4 (d) VALUES (?)">>, [3.14159]),
    {ok, _, [[Value]]} = mysql:query(Pid, <<"SELECT d FROM dec13_4">>),
    ?assertEqual(3.14, Value),
    ok = mysql:query(Pid, <<"DROP TABLE dec13_4">>),
    ok = mysql:stop(Pid).

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
    %% TINYINT UNSIGNED
    ok = mysql:query(Pid, "CREATE TABLE tuint (i TINYINT UNSIGNED)"),
    write_read_text_binary(Pid, 240, <<"240">>, <<"tuint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE tuint"),
    %% SMALLINT
    ok = mysql:query(Pid, "CREATE TABLE sint (i SMALLINT)"),
    write_read_text_binary(Pid, 32000, <<"32000">>, <<"sint">>, <<"i">>),
    write_read_text_binary(Pid, -32000, <<"-32000">>, <<"sint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE sint"),
    %% SMALLINT UNSIGNED
    ok = mysql:query(Pid, "CREATE TABLE suint (i SMALLINT UNSIGNED)"),
    write_read_text_binary(Pid, 64000, <<"64000">>, <<"suint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE suint"),
    %% MEDIUMINT
    ok = mysql:query(Pid, "CREATE TABLE mint (i MEDIUMINT)"),
    write_read_text_binary(Pid, 8388000, <<"8388000">>,
                           <<"mint">>, <<"i">>),
    write_read_text_binary(Pid, -8388000, <<"-8388000">>,
                           <<"mint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE mint"),
    %% MEDIUMINT UNSIGNED
    ok = mysql:query(Pid, "CREATE TABLE muint (i MEDIUMINT UNSIGNED)"),
    write_read_text_binary(Pid, 16777000, <<"16777000">>,
                           <<"muint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE muint"),
    %% BIGINT
    ok = mysql:query(Pid, "CREATE TABLE bint (i BIGINT)"),
    write_read_text_binary(Pid, 123456789012, <<"123456789012">>,
                           <<"bint">>, <<"i">>),
    write_read_text_binary(Pid, -123456789012, <<"-123456789012">>,
                           <<"bint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE bint"),
    %% BIGINT UNSIGNED
    ok = mysql:query(Pid, "CREATE TABLE buint (i BIGINT UNSIGNED)"),
    write_read_text_binary(Pid, 18446744073709551000,
                           <<"18446744073709551000">>,
                           <<"buint">>, <<"i">>),
    ok = mysql:query(Pid, "DROP TABLE buint").

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

json(Pid) ->
    Version = db_version_string(Pid),
    try
        is_mariadb(Version) andalso throw(no_mariadb),
        Version1 = parse_db_version(Version),
        Version1 >= [5, 7, 8] orelse throw(version_too_small)
    of _ ->
        test_valid_json(Pid),
        test_invalid_json(Pid)
    catch
        throw:no_mariadb ->
            error_logger:info_msg("Skipping JSON test, not supported on"
                                  " MariaDB.~n");
        throw:version_too_small ->
            error_logger:info_msg("Skipping JSON test. Current MySQL version"
                                  " is ~s. Required version is >= 5.7.8.~n",
                                  [Version])
    end.

test_valid_json(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE json_t (json_c JSON)"),
    Value = <<"'{\"a\": 1, \"b\": {\"c\": [1, 2, 3, 4]}}'">>,
    Expected = <<"{\"a\": 1, \"b\": {\"c\": [1, 2, 3, 4]}}">>,
    write_read_text_binary(Pid, Expected, Value,
                           <<"json_t">>, <<"json_c">>),
    ok = mysql:query(Pid, "DROP TABLE json_t").

test_invalid_json(Pid) ->
    ok = mysql:query(Pid, "CREATE TABLE json_t (json_c JSON)"),
    InvalidJson = <<"'{\"a\": \"c\": 2}'">>,
    ?assertMatch({error,{3140, <<"22032">>, _}},
                 mysql:query(Pid, <<"INSERT INTO json_t (json_c)"
                                    " VALUES (", InvalidJson/binary,
                                    ")">>)),
    ok = mysql:query(Pid, "DROP TABLE json_t").

microseconds(Pid) ->
    %% Check whether we have the required version for this testcase.
    Version = db_version_string(Pid),
    try
        Version1 = parse_db_version(Version),
        Version1 >= [5, 6, 4] orelse throw(nope)
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

invalid_params(Pid) ->
    {ok, StmtId} = mysql:prepare(Pid, "SELECT ?"),
    ?assertError(badarg, mysql:execute(Pid, StmtId, [x])),
    ?assertError(badarg, mysql:query(Pid, "SELECT ?", [x])),
    ok = mysql:unprepare(Pid, StmtId).

load_data_local_infile(Pid, Cwd) ->
    File = iolist_to_binary(filename:join([Cwd, "load_local_infile_test.csv"])),
    ok = file:write_file(File, <<"1;value 1\n2;value 2\n">>),
    ok = mysql:query(Pid, <<"CREATE TABLE load_local_test (id int, value blob)">>),
    ok = mysql:query(Pid, <<"LOAD DATA LOCAL "
                            "INFILE '", File/binary, "' "
                            "INTO TABLE load_local_test "
                            "FIELDS TERMINATED BY ';' "
                            "LINES TERMINATED BY '\\n'">>),
    ok = file:delete(File),
    {ok, Columns, Rows} = mysql:query(Pid,
                                      <<"SELECT * FROM load_local_test ORDER BY id">>),
    ?assertEqual([<<"id">>, <<"value">>], Columns),
    ?assertEqual([[1, <<"value 1">>], [2, <<"value 2">>]], Rows),
    ok = mysql:query(Pid, <<"DROP TABLE load_local_test">>).

load_data_local_infile_missing(Pid, Cwd) ->
    File = iolist_to_binary(filename:join([Cwd, "load_local_infile_missing_test.csv"])),
    ok = mysql:query(Pid, <<"CREATE TABLE load_local_test (id int, value blob)">>),
    Result = mysql:query(Pid, <<"LOAD DATA LOCAL "
                                "INFILE '", File/binary, "' "
                                "INTO TABLE load_local_test "
                                "FIELDS TERMINATED BY ';' "
                                "LINES TERMINATED BY '\\n'">>),
    FilenameSize=byte_size(File),
    ?assertMatch({error, {-2, undefined, <<"The server requested a file which could "
                                           "not be opened by the client: ",
                                           File:FilenameSize/binary, _/binary>>}},
                 Result),
    ok = mysql:query(Pid, <<"DROP TABLE load_local_test">>).

load_data_local_infile_not_allowed(Pid, Cwd) ->
    File = iolist_to_binary(filename:join([Cwd, "../load_local_infile_not_allowed_test.csv"])),
    ok = mysql:query(Pid, <<"CREATE TABLE load_local_test (id int, value blob)">>),
    Result = mysql:query(Pid, <<"LOAD DATA LOCAL "
                                "INFILE '", File/binary, "' "
                                "INTO TABLE load_local_test "
                                "FIELDS TERMINATED BY ';' "
                                "LINES TERMINATED BY '\\n'">>),
    ?assertEqual({error, {-1, undefined, <<"The server requested a file not permitted "
                                           "by the client: ", File/binary>>}}, Result),
    ok = mysql:query(Pid, <<"DROP TABLE load_local_test">>).

load_data_local_infile_multi(Pid, Cwd) ->
    File = iolist_to_binary(filename:join([Cwd, "load_local_infile_test.csv"])),
    ok = file:write_file(File, <<"1;value 1\n2;value 2\n">>),
    ok = mysql:query(Pid, <<"CREATE TABLE load_local_test (id int, value blob)">>),
    {ok, [Res1, Res2]} = mysql:query(Pid, <<"SELECT 'foo'; "
                                            "LOAD DATA LOCAL "
                                            "INFILE '", File/binary, "' "
                                            "INTO TABLE load_local_test "
                                            "FIELDS TERMINATED BY ';' "
                                            "LINES TERMINATED BY '\\n'; "
                                            "SELECT 'bar'">>),
    ok = file:delete(File),
    ?assertEqual({[<<"foo">>], [[<<"foo">>]]}, Res1),
    ?assertEqual({[<<"bar">>], [[<<"bar">>]]}, Res2),
    {ok, Columns, Rows} = mysql:query(Pid,
                                      <<"SELECT * FROM load_local_test ORDER BY id">>),
    ?assertEqual([<<"id">>, <<"value">>], Columns),
    ?assertEqual([[1, <<"value 1">>], [2, <<"value 2">>]], Rows),
    ok = mysql:query(Pid, <<"DROP TABLE load_local_test">>).

%% @doc Tests write and read in text and the binary protocol, all combinations.
%% This helper function assumes an empty table with a single column.
write_read_text_binary(Conn, Term, SqlLiteral, Table, Column) ->
    SelectQuery = <<"SELECT ", Column/binary, " FROM ", Table/binary>>,
    {ok, SelectStmt} = mysql:prepare(Conn, SelectQuery),

    %% Insert as text, read text and binary, delete
    InsertQuery = <<"INSERT INTO ", Table/binary, " (", Column/binary, ")"
                    " VALUES (", SqlLiteral/binary, ")">>,
    ok = mysql:query(Conn, InsertQuery),
    R = mysql:query(Conn, SelectQuery),
    ?assertEqual({ok, [Column], [[Term]]}, R),
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
         mysql:stop(Pid)
     end,
     {with, [fun (Pid) ->
                 %% SLEEP was added in MySQL 5.0.12
                 check_sleep_timeout_result(
                              mysql:query(Pid, <<"SELECT SLEEP(5)">>, 40)),

                 %% A query after an interrupted query shouldn't get a timeout.
                 ?assertMatch({ok,[<<"42">>], [[42]]},
                              mysql:query(Pid, <<"SELECT 42">>)),

                 %% Parametrized query
                 check_sleep_timeout_result(
                              mysql:query(Pid, <<"SELECT SLEEP(?)">>, [5], 40)),

                 %% Prepared statement
                 {ok, Stmt} = mysql:prepare(Pid, <<"SELECT SLEEP(?)">>),
                 check_sleep_timeout_result(
                              mysql:execute(Pid, Stmt, [5], 40)),
                 ok = mysql:unprepare(Pid, Stmt)
             end]}}.

check_sleep_timeout_result({error, {1317, <<"70100">>,
                                    <<"Query execution was ", _/binary>>}}) ->
    %% MariaDB 10.3 on TravisCI returns this when sleep is interrupted.
    ok;
check_sleep_timeout_result(Result) ->
    %% Sleep returns 1 when aborted
    ?assertMatch({ok, [<<"SLEEP", _/binary>>], [[1]]}, Result).

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
         mysql:stop(Pid)
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
    {error, {_, _, _}} = mysql:query(Conn, "Lorem ipsum dolor sit amet", [4]).

%% --- simple gen_server callbacks ---

gen_server_coverage_test() ->
    {noreply, state} = mysql_conn:handle_cast(foo, state),
    {noreply, state} = mysql_conn:handle_info(foo, state),
    ok = mysql_conn:terminate(kill, state).

%% --- Utility functions
db_version_string(Pid) ->
  {ok, _, [[Version]]} = mysql:query(Pid, <<"SELECT @@version">>),
  Version.

is_mariadb(Version) ->
    binary:match(Version, <<"MariaDB">>) =/= nomatch.

parse_db_version(Version) ->
  %% Remove stuff after dash for e.g. "5.5.40-0ubuntu0.12.04.1-log"
  [Version1 | _] = binary:split(Version, <<"-">>),
  lists:map(fun binary_to_integer/1,
            binary:split(Version1, <<".">>, [global])).

is_access_denied({1045, <<"28000">>, <<"Access denie", _/binary>>}) ->
    true; % MySQL 5.x, etc.
is_access_denied({1698, <<"28000">>, <<"Access denie", _/binary>>}) ->
    true; % MariaDB 10.3.15
is_access_denied({1251, <<"08004">>, <<"Client does not support authentication "
                                       "protocol requested", _/binary>>}) ->
    true; % This has been observed with MariaDB 10.3.13
is_access_denied(_) ->
    false.
