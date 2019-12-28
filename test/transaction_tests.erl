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
-module(transaction_tests).

-include_lib("eunit/include/eunit.hrl").

-define(user,     "otptest").
-define(password, "otptest").

single_connection_test_() ->
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
         [{"Simple atomic",        fun () -> simple_atomic(Pid) end},
          {"Simple aborted",       fun () -> simple_aborted(Pid) end},
          {"Nested atomic",        fun () -> nested_atomic(Pid) end},
          {"Nested inner aborted", fun () -> nested_inner_aborted(Pid) end},
          {"Implicit commit",      fun () -> implicit_commit(Pid) end}]
     end}.

application_process_kill_test_() ->
    {timeout, 30, fun application_process_kill/0}.

application_process_kill() ->
    %% This test case simulates a setup where the connection is owned by
    %% another process, e.g. a connection pool. An application process (e.g.
    %% a cowboy worker) is killed when it using a connection in a transaction.
    %% In this case, the connection should not go back in the pool as it would
    %% be in a bad state. Therefore, the connection is monitoring the process
    %% starting a transaction and kills itself if the caller dies.
    {ok, Pid} = mysql:start_link([
        {user, ?user},
        {password, ?password},
        {query_cache_time, 50},
        {log_warnings, false}
    ]),

    unlink(Pid),
    Mref = erlang:monitor(process, Pid),

    ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
    ok = mysql:query(Pid, <<"CREATE DATABASE otptest">>),
    ok = mysql:query(Pid, <<"USE otptest">>),
    ok = mysql:query(Pid, <<"CREATE TABLE foo (bar INT) engine=InnoDB">>),

    ?assertNot(mysql:in_transaction(Pid)),
    ?assert(is_process_alive(Pid)),

    Self = self(),

    AppPid = spawn(fun() ->
        mysql:transaction(Pid, fun () ->
            ok = mysql:query(Pid, "INSERT INTO foo (bar) VALUES (42)"),
            Self! killme,
            receive after 10000 -> throw(too_long) end,
            ok
        end)
    end),

    %% Wait for the AppPid to be ready to be killed when in a transaction
    receive killme -> ok end,

    %% Kill AppPid, the process using the connection, capturing the noise
    {ok, ok, LoggedErrors} = error_logger_acc:capture(fun () ->
        exit(AppPid, kill),
        receive
            {'DOWN', Mref, process, Pid, {application_process_died, AppPid}} ->
                ok
        after 10000 ->
            throw(too_long)
        end
    end),
    %% Check that we got the expected error log noise
    ?assertMatch([{error, "Connection Id" ++ _},     %% from mysql_conn
                  {error, "** Generic server" ++ _}, %% from gen_server
                  {error_report, _}], LoggedErrors),

    ?assertNot(is_process_alive(Pid)),

    %% Check that the transaction was not commited
    {ok, Pid2} = mysql:start_link([
        {user, ?user},
        {password, ?password},
        {query_cache_time, 50},
        {log_warnings, false}
    ]),
    ok = mysql:query(Pid2, <<"USE otptest">>),
    ?assertMatch({ok, _, []},
                 mysql:query(Pid2, <<"SELECT * from foo where bar = 42">>)),
    ok = mysql:query(Pid2, <<"DROP DATABASE otptest">>),
    mysql:stop(Pid2).

simple_atomic(Pid) ->
    ?assertNot(mysql:in_transaction(Pid)),
    Result = mysql:transaction(Pid, fun () ->
                 ok = mysql:query(Pid, "INSERT INTO foo (bar) VALUES (42)"),
                 ?assert(mysql:in_transaction(Pid)),
                 hello
             end),
    ?assertEqual({atomic, hello}, Result),
    ?assertNot(mysql:in_transaction(Pid)),
    ok = mysql:query(Pid, "DELETE FROM foo").

simple_aborted(Pid) ->
    ok = mysql:query(Pid, "INSERT INTO foo VALUES (9)"),
    ?assertEqual({ok, [<<"bar">>], [[9]]},
                 mysql:query(Pid, "SELECT bar FROM foo")),
    Result = mysql:transaction(Pid, fun () ->
                 ok = mysql:query(Pid, "INSERT INTO foo VALUES (42)"),
                 ?assertMatch({ok, _, [[2]]},
                              mysql:query(Pid, "SELECT COUNT(*) FROM foo")),
                 error(hello)
             end),
    ?assertMatch({aborted, {hello, Stacktrace}} when is_list(Stacktrace),
                 Result),
    ?assertEqual({ok, [<<"bar">>], [[9]]},
                 mysql:query(Pid, "SELECT bar FROM foo")),
    ok = mysql:query(Pid, "DELETE FROM foo"),
    %% Also check the abort Reason for throw and exit.
    ?assertEqual({aborted, {throw, foo}},
                 mysql:transaction(Pid, fun () -> throw(foo) end)),
    ?assertEqual({aborted, foo},
                 mysql:transaction(Pid, fun () -> exit(foo) end)).

nested_atomic(Pid) ->
    OuterResult = mysql:transaction(Pid, fun () ->
        ok = mysql:query(Pid, "INSERT INTO foo VALUES (9)"),
        InnerResult = mysql:transaction(Pid, fun () ->
            ok = mysql:query(Pid, "INSERT INTO foo VALUES (42)"),
            inner
        end),
        ?assertEqual({atomic, inner}, InnerResult),
        outer
    end),
    ?assertMatch({ok, _, [[2]]}, mysql:query(Pid, "SELECT COUNT(*) FROM foo")),
    ok = mysql:query(Pid, "DELETE FROM foo"),
    ?assertEqual({atomic, outer}, OuterResult).

nested_inner_aborted(Pid) ->
    OuterResult = mysql:transaction(Pid, fun () ->
        ok = mysql:query(Pid, "INSERT INTO foo VALUES (9)"),
        InnerResult = mysql:transaction(Pid, fun () ->
            ok = mysql:query(Pid, "INSERT INTO foo VALUES (42)"),
            throw(inner)
        end),
        ?assertEqual({aborted, {throw, inner}}, InnerResult),
        outer
    end),
    ?assertMatch({ok, _, [[9]]}, mysql:query(Pid, "SELECT bar FROM foo")),
    ok = mysql:query(Pid, "DELETE FROM foo"),
    ?assertEqual({atomic, outer}, OuterResult).

implicit_commit(Conn) ->
    %% This causes an implicit commit in a nested transaction.
    Query = "ALTER TABLE foo ADD baz INT",
    ?assertError({implicit_commit, Query}, mysql:transaction(Conn, fun () ->
        mysql:transaction(Conn, fun () ->
            mysql:query(Conn, Query)
        end)
    end)),
    ?assertNot(mysql:in_transaction(Conn)).

%% -----------------------------------------------------------------------------

deadlock_test_() ->
    {setup,
     fun () ->
         {ok, Conn1} = mysql:start_link([{user, ?user}, {password, ?password}]),
         ok = mysql:query(Conn1, <<"CREATE DATABASE IF NOT EXISTS otptest">>),
         ok = mysql:query(Conn1, <<"USE otptest">>),
         ok = mysql:query(Conn1, <<"CREATE TABLE foo (k INT PRIMARY KEY, v INT)"
                                   " engine=InnoDB">>),
         ok = mysql:query(Conn1, "INSERT INTO foo (k,v) VALUES (1,0), (2,0)"),
         {ok, Conn2} = mysql:start_link([{user, ?user}, {password, ?password}]),
         ok = mysql:query(Conn2, <<"USE otptest">>),
         {Conn1, Conn2}
     end,
     fun ({Conn1, Conn2}) ->
         ok = mysql:query(Conn1, <<"DROP DATABASE otptest">>, 1000),
         mysql:stop(Conn1),
         mysql:stop(Conn2)
     end,
     fun (Conns) ->
             [{"Plain queries", fun () -> deadlock_plain_queries(Conns) end},
              {"Prep stmts", fun () -> deadlock_prepared_statements(Conns) end},
              {"No retry", fun () -> deadlock_no_retry(Conns) end},
              {"Lock wait timeout", fun () -> lock_wait_timeout(Conns) end}]
     end}.

flush_inbox() ->
    receive _ -> flush_inbox() after 0 -> ok end.

deadlock_plain_queries({Conn1, Conn2}) ->
    {ok, _, [[2]]} = mysql:query(Conn1, "SELECT COUNT(*) FROM foo"),
    MainPid = self(),
    %?debugMsg("\nExtra output from the deadlock test:"),

    %% Spawn worker 2 to lock rows; first in table foo, then in bar.
    Worker2 = spawn_link(fun () ->
        {atomic, ok} = mysql:transaction(Conn2, fun () ->
            MainPid ! start,
            ok = mysql:query(Conn2, "UPDATE foo SET v = 2 WHERE k = 2"),
            %% Sync. Send 'go' to worker 1 multiple times in case it restarts.
            MainPid ! go, MainPid ! go, MainPid ! go,
            receive go -> ok after 10000 -> throw(too_long) end,
            {atomic, ok} = mysql:transaction(Conn2, fun () ->
                %% Nested transaction, just to make sure we can handle nested.
                ok = mysql:query(Conn2, "UPDATE foo SET v = 2 WHERE k = 1")
            end),
            ok
        end),
        MainPid ! done
    end),

    %% Do worker 1's job and lock the rows in the opposite order.
    {atomic, ok} = mysql:transaction(Conn1, fun () ->
        MainPid ! start,
        ok = mysql:query(Conn1, "UPDATE foo SET v = 1 WHERE k = 1"),
        %% Sync. Send 'go' to worker 2 multiple times in case it restarts.
        Worker2 ! go, Worker2 ! go, Worker2 ! go,
        receive go -> ok after 10000 -> throw(too_long) end,
        {atomic, ok} = mysql:transaction(Conn1, fun () ->
            %% Nested transaction, just to make sure we can handle nested.
            ok = mysql:query(Conn1, "UPDATE foo SET v = 1 WHERE k = 2")
        end),
        ok
    end),

    %% Wait for a reply from worker 2 to make sure it is done.
    receive done -> ok end,

    %% None of the connections should be in a transaction at this point
    ?assertNot(mysql:in_transaction(Conn1)),
    ?assertNot(mysql:in_transaction(Conn2)),

    %% Make sure we got at least 3 start messages, i.e. at least 1 restart.
    ?assertEqual(ok, receive start -> ok after 0 -> no_worker_ever_started end),
    ?assertEqual(ok, receive start -> ok after 0 -> only_one_worker_started end),
    ?assertEqual(ok, receive start -> ok after 0 -> there_was_no_deadlock end),
    flush_inbox().

%% This case is very similar to the above test. We use prepared statements
%% instead of plain queries. (Some lines of code in the implementation differ.)
deadlock_prepared_statements({Conn1, Conn2}) ->
    {ok, _, [[2]]} = mysql:query(Conn1, "SELECT COUNT(*) FROM foo"),
    {ok, upd} = mysql:prepare(Conn1, upd, "UPDATE foo SET v = ? WHERE k = ?"),
    {ok, upd} = mysql:prepare(Conn2, upd, "UPDATE foo SET v = ? WHERE k = ?"),
    MainPid = self(),

    %% Spawn worker 2 to lock rows; first in table foo, then in bar.
    Worker2 = spawn_link(fun () ->
        {atomic, ok} = mysql:transaction(Conn2, fun () ->
            MainPid ! start,
            ok = mysql:execute(Conn2, upd, [2, 2]),
            %% Sync. Send 'go' to worker 1 multiple times in case it restarts.
            MainPid ! go, MainPid ! go, MainPid ! go,
            receive go -> ok end,
            {atomic, ok} = mysql:transaction(Conn2, fun () ->
                %% Nested transaction, just to make sure we can handle nested.
                ok = mysql:execute(Conn2, upd, [2, 1])
            end),
            ok
        end, 2),
        MainPid ! done
    end),

    %% Do worker 1's job and lock the rows in the opposite order.
    {atomic, ok} = mysql:transaction(Conn1, fun () ->
        MainPid ! start,
        ok = mysql:execute(Conn1, upd, [1, 1]),
        %% Sync. Send 'go' to worker 2 multiple times in case it restarts.
        Worker2 ! go, Worker2 ! go, Worker2 ! go,
        receive go -> ok end,
        {atomic, ok} = mysql:transaction(Conn1, fun () ->
            %% Nested transaction, just to make sure we can handle nested.
            ok = mysql:execute(Conn1, upd, [1, 2])
        end),
        ok
    end, 2),

    %% Wait for a reply from worker 2.
    receive done -> ok end,

    %% None of the connections should be in a transaction at this point
    ?assertNot(mysql:in_transaction(Conn1)),
    ?assertNot(mysql:in_transaction(Conn2)),

    %% Make sure we got at least 3 start messages, i.e. at least 1 restart.
    ?assertEqual(ok, receive start -> ok after 0 -> no_worker_ever_started end),
    ?assertEqual(ok, receive start -> ok after 0 -> only_one_worker_started end),
    ?assertEqual(ok, receive start -> ok after 0 -> there_was_no_deadlock end),
    flush_inbox().

deadlock_no_retry({Conn1, Conn2}) ->
    {ok, _, [[2]]} = mysql:query(Conn1, "SELECT COUNT(*) FROM foo"),
    MainPid = self(),
    %?debugMsg("\nExtra output from the deadlock test:"),

    %% Spawn worker 2 to lock rows; first in table foo, then in bar.
    Worker2 = spawn_link(fun () ->
        Result = mysql:transaction(Conn2, fun () ->
            MainPid ! start,
            ok = mysql:query(Conn2, "UPDATE foo SET v = 2 WHERE k = 2"),
            %% Sync. Send 'go' to worker 1 multiple times in case it restarts.
            MainPid ! go, MainPid ! go, MainPid ! go,
            receive go -> ok after 10000 -> throw(too_long) end,
            {atomic, ok} = mysql:transaction(Conn2, fun () ->
                %% Nested transaction, just to make sure we can handle nested.
                ok = mysql:query(Conn2, "UPDATE foo SET v = 2 WHERE k = 1")
            end),
            ok
        end, 0),
        MainPid ! {done, Result}
    end),

    %% Do worker 1's job and lock the rows in the opposite order.
    Result1 = mysql:transaction(Conn1, fun () ->
        MainPid ! start,
        ok = mysql:query(Conn1, "UPDATE foo SET v = 1 WHERE k = 1"),
        %% Sync. Send 'go' to worker 2 multiple times in case it restarts.
        Worker2 ! go, Worker2 ! go, Worker2 ! go,
        receive go -> ok after 10000 -> throw(too_long) end,
        {atomic, ok} = mysql:transaction(Conn1, fun () ->
            %% Nested transaction, just to make sure we can handle nested.
            ok = mysql:query(Conn1, "UPDATE foo SET v = 1 WHERE k = 2")
        end),
        ok
    end, 0),

    %% Wait for a reply from worker 2 to make sure it is done.
    Result2 = receive {done, Result} -> Result end,

    %% Check that one of them was ok, the other one was aborted.
    [ResultAborted, ResultAtomic] = lists:sort([Result1, Result2]),
    ?assertEqual({atomic, ok}, ResultAtomic),
    ?assertMatch({aborted,
                  {{1213, <<"40001">>, <<"Deadlock", _/binary>>}, _Trace}},
                 ResultAborted),

    %% None of the connections should be in a transaction at this point
    ?assertNot(mysql:in_transaction(Conn1)),
    ?assertNot(mysql:in_transaction(Conn2)),

    %% Make sure we got exactly 2 start messages, i.e. there was no restart.
    ?assertEqual(ok, receive start -> ok after 0 -> no_worker_ever_started end),
    ?assertEqual(ok, receive start -> ok after 0 -> only_one_worker_started end),
    ?assertEqual(ok, receive start -> there_was_a_restart after 0 -> ok end),
    flush_inbox().

lock_wait_timeout({_Conn1, Conn2} = Conns) ->
    %% Set the lowest timeout possible to speed up the test.
    case mysql:query(Conn2, "SET innodb_lock_wait_timeout = 1") of
        ok ->
            lock_wait_timeout1(Conns);
        {error, {1238, _, <<"Variable 'innodb_lock_wait_timeout' is a read on",
                            _/binary>>}} ->
            error_logger:info_msg("Can't set lock wait timeout in this server"
                                  " version. Skipping the lock wait timeout"
                                  " test.\n")
    end.

%% Continuation of lock_wait_timeout/1.
lock_wait_timeout1({Conn1, Conn2}) ->    
    {ok, _, [[1]]} = mysql:query(Conn2, "SELECT COUNT(*) FROM foo WHERE k = 1"),
    MainPid = self(),

    %% Create a worker that takes the lock and sleeps on it.
    LockingWorker = spawn_link(fun () ->
        {atomic, ok} = mysql:transaction(Conn1, fun () ->
            ok = mysql:query(Conn1, "UPDATE foo SET v = 0 WHERE k = 1"),
            MainPid ! go,
            receive release -> ok end
        end),
        MainPid ! done
    end),

    %% Wait for the locking worker to take the lock.
    receive go -> ok end,
    {atomic, ok} = mysql:transaction(Conn2, fun () ->
        ?assertMatch({error, {1205, _, <<"Lock wait timeout", _/binary>>}},
                     mysql:query(Conn2, "UPDATE foo SET v = 42 WHERE k = 1")),
        ok
    end),

    %% Wake the sleeping worker.
    LockingWorker ! release,
    receive done -> ok end,
    flush_inbox().
