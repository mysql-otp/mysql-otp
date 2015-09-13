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
         exit(Pid, normal)
     end,
     fun (Pid) ->
         [{"Simple atomic",        fun () -> simple_atomic(Pid) end},
          {"Simple aborted",       fun () -> simple_aborted(Pid) end},
          {"Nested atomic",        fun () -> nested_atomic(Pid) end},
          {"Nested inner aborted", fun () -> nested_inner_aborted(Pid) end},
          {"Implicit commit",      fun () -> implicit_commit(Pid) end}]
     end}.

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
         exit(Conn1, normal),
         exit(Conn2, normal)
     end,
     fun (Conns) ->
         [{"Plain queries", fun () -> deadlock_plain_queries(Conns) end},
          {"Prep stmts", fun () -> deadlock_prepared_statements(Conns) end},
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
            %?debugMsg("Worker 2: Starting. First get a lock on row 2."),
            ok = mysql:query(Conn2, "UPDATE foo SET v = 2 WHERE k = 2"),
            %?debugMsg("Worker 2: Got lock on foo. Now wait for signal from 1."),
            %% Sync. Send 'go' to worker 1 multiple times in case it restarts.
            MainPid ! go, MainPid ! go, MainPid ! go,
            receive go -> ok after 10000 -> throw(too_long) end,
            %?debugMsg("Worker 2: Got signal from 1. Now get a lock on row 1."),
            {atomic, ok} = mysql:transaction(Conn2, fun () ->
                %% Nested transaction, just to make sure we can handle nested.
                ok = mysql:query(Conn2, "UPDATE foo SET v = 2 WHERE k = 1")
            end),
            %?debugMsg("Worker 2: Got both locks and is done."),
            ok
        end),
        MainPid ! done
    end),

    %% Do worker 1's job and lock the rows in the opposite order.
    {atomic, ok} = mysql:transaction(Conn1, fun () ->
        MainPid ! start,
        %?debugMsg("Worker 1: Starting. First get a lock on row 1."),
        ok = mysql:query(Conn1, "UPDATE foo SET v = 1 WHERE k = 1"),
        %?debugMsg("Worker 1: Got lock on bar. Now wait for signal from 2."),
        %% Sync. Send 'go' to worker 2 multiple times in case it restarts.
        Worker2 ! go, Worker2 ! go, Worker2 ! go,
        receive go -> ok after 10000 -> throw(too_long) end,
        %?debugMsg("Worker 1: Got signal from 2. Now get lock on row 2."),
        {atomic, ok} = mysql:transaction(Conn1, fun () ->
            %% Nested transaction, just to make sure we can handle nested.
            ok = mysql:query(Conn1, "UPDATE foo SET v = 1 WHERE k = 2")
        end),
        %?debugMsg("Worker 1: Got both locks and is done."),
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
    {aborted, Reason} = mysql:transaction(Conn2, fun () ->
        ok = mysql:query(Conn2, "UPDATE foo SET v = 42 WHERE k = 1")
    end),
    ?assertMatch({{1205, _, <<"Lock wait timeout", _/binary>>}, _Trace},
                 Reason),

    %% Wake the sleeping worker.
    LockingWorker ! release,
    receive done -> ok end,
    flush_inbox().
