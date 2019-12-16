%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2019 Jan Uhlig
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
-module(mysql_change_user_tests).

-include_lib("eunit/include/eunit.hrl").

-define(user1,     "otptest").
-define(password1, "otptest").
-define(user2,     "otptest2").
-define(password2, "otptest2").

%% Ensure that the current user can be changed to another user
%% when given correct credentials.
correct_credentials_test() ->
    Pid = connect_db(?user1, ?password1),
    ?assertEqual(ok, mysql:change_user(Pid, ?user2, ?password2)),
    ?assert(is_current_user(Pid, ?user2)),
    mysql:stop(Pid),
    ok.

%% Ensure that change user fails when given incorrect credentials,
%% and that the current user still works.
incorrect_credentials_fail_test() ->
    Pid = connect_db(?user1, ?password1),
    TrapExit = erlang:process_flag(trap_exit, true),
    {ok, {Ret, ExitReason}, Logged} = error_logger_acc:capture(fun () ->
        ChangeUserReturn = mysql:change_user(Pid, ?user2, ?password1),
        receive {'EXIT', Pid, Reason} -> {ChangeUserReturn, Reason}
        after 1000 -> error(no_exit_message)
        end
    end),
    erlang:process_flag(trap_exit, TrapExit),
    ?assertMatch([{error, "Connection Id " ++ _}, % closing with reason: cha...
                  {error, "** Generic server" ++ _},
                  {error_report, {crash_report, _}}], Logged),
    ?assertMatch({error, {1045, <<"28000">>, <<"Access denied", _/binary>>}},
                 Ret),
    ?assertEqual(change_user_failed, ExitReason),
    ?assertExit(noproc, mysql:stop(Pid)),
    ok.

%% Ensure that user variables are reset after a successful change user
%% operation.
reset_variables_test() ->
    Pid = connect_db(?user1, ?password1),
    ok = mysql:query(Pid, <<"SET @foo=123">>),
    ?assertEqual(ok, mysql:change_user(Pid, ?user2, ?password2)),
    ?assert(is_current_user(Pid, ?user2)),
    ?assertEqual({ok,
                  [<<"@foo">>],
                  [[null]]},
                 mysql:query(Pid, <<"SELECT @foo">>)),
    mysql:stop(Pid),
    ok.

%% Ensure that temporary tables are reset after a successful change user
%% operation.
reset_temptables_test() ->
    Pid = connect_db(?user1, ?password1),
    ok = mysql:query(Pid, <<"CREATE DATABASE IF NOT EXISTS otptest">>),
    ok = mysql:query(Pid, <<"CREATE TEMPORARY TABLE otptest.foo (bar INT)">>),
    ?assertEqual(ok, mysql:change_user(Pid, ?user2, ?password2)),
    ?assert(is_current_user(Pid, ?user2)),
    ?assertMatch({error,
                  {1146, <<"42S02">>, _}},
                 mysql:query(Pid, <<"SELECT * FROM otptest.foo">>)),
    ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
    mysql:stop(Pid),
    ok.

%% Ensure that change user fails when inside an unmanaged transaction.
fail_in_unmanaged_transaction_test() ->
    Pid = connect_db(?user1, ?password1),
    ok = mysql:query(Pid, <<"BEGIN">>),
    ?assert(mysql:in_transaction(Pid)),
    ?assertError(change_user_in_transaction,
                 mysql:change_user(Pid, ?user2, ?password2)),
    ?assert(is_current_user(Pid, ?user1)),
    ?assert(mysql:in_transaction(Pid)),
    mysql:stop(Pid),
    ok.

%% Ensure that change user fails when inside a managed transaction.
fail_in_managed_transaction_test() ->
    Pid = connect_db(?user1, ?password1),
    ?assertError(change_user_in_transaction,
                 mysql:transaction(Pid,
                                   fun () -> mysql:change_user(Pid,
                                                               ?user2,
                                                               ?password2)
                                   end)),
    ?assert(is_current_user(Pid, ?user1)),
    mysql:stop(Pid),
    ok.

with_db_test() ->
    Pid = connect_db(?user1, ?password1),
    ok = mysql:query(Pid, <<"CREATE DATABASE IF NOT EXISTS otptest">>),
    ?assertEqual(ok, mysql:change_user(Pid, ?user2, ?password2, [{database, <<"otptest">>}])),
    ?assert(is_current_user(Pid, ?user2)),
    ?assertEqual({ok,
                  [<<"DATABASE()">>],
                  [[<<"otptest">>]]},
                 mysql:query(Pid, <<"SELECT DATABASE()">>)),
    ok = mysql:query(Pid, <<"DROP DATABASE IF EXISTS otptest">>),
    mysql:stop(Pid),
    ok.

execute_queries_test() ->
    Pid = connect_db(?user1, ?password1),
    ?assertEqual(ok, mysql:change_user(Pid, ?user2, ?password2, [{queries, [<<"SET @foo=123">>]}])),
    ?assert(is_current_user(Pid, ?user2)),
    ?assertEqual({ok,
                  [<<"@foo">>],
                  [[123]]},
                 mysql:query(Pid, <<"SELECT @foo">>)),
    mysql:stop(Pid),
    ok.

execute_queries_failure_test() ->
    Pid = connect_db(?user1, ?password1),
    erlang:process_flag(trap_exit, true),
    {ok, Ret, Logged} = error_logger_acc:capture(fun () ->
        Ret1 = mysql:change_user(Pid, ?user2, ?password2, [{queries, [<<"foo">>]}]),
        receive {'EXIT', Pid, _Reason} -> Ret1
        after 1000 -> error(no_exit_message)
        end
    end),
    ?assertMatch([{error, "Connection Id " ++ _}, % closing with reason: {1064,
                  {error, "** Generic server" ++ _},
                  {error_report, {crash_report, _}}], Logged),
    {error, Reason} = Ret,
    ?assertMatch({1064, <<"42000">>, <<"You have an erro", _/binary>>}, Reason),
    erlang:process_flag(trap_exit, false).

prepare_statements_test() ->
    Pid = connect_db(?user1, ?password1),
    ?assertEqual(ok, mysql:change_user(Pid, ?user2, ?password2,
                                       [{prepare, [{foo, <<"SELECT ? AS foo">>}]}])),
    ?assert(is_current_user(Pid, ?user2)),
    ?assertEqual({ok,
                  [<<"foo">>],
                  [[123]]},
                 mysql:execute(Pid, foo, [123])),
    mysql:stop(Pid),
    ok.

prepare_statements_failure_test() ->
    Pid = connect_db(?user1, ?password1),
    erlang:process_flag(trap_exit, true),
    {ok, Ret, Logged} = error_logger_acc:capture(fun () ->
        Ret1 = mysql:change_user(Pid, ?user2, ?password2,
                                 [{prepare, [{foo, <<"foo">>}]}]),
       receive {'EXIT', Pid, _Reason} -> Ret1
       after 1000 -> error(no_exit_message)
       end
    end),
    ?assertMatch([{error, "Connection Id " ++ _}, % closing with reason: {1064,
                  {error, "** Generic server" ++ _},
                  {error_report, {crash_report, _}}], Logged),
    {error, Reason} = Ret,
    ?assertMatch({1064, <<"42000">>, <<"You have an erro", _/binary>>}, Reason),
    erlang:process_flag(trap_exit, false).


connect_db(User, Password) ->
    {ok, Pid} = mysql:start_link([{user, User}, {password, Password},
                                  {log_warnings, false}]),
    Pid.

is_current_user(Pid, User) when is_binary(User) ->
    {ok, [<<"CURRENT_USER()">>], [[CurUser]]}=mysql:query(Pid, <<"SELECT CURRENT_USER()">>),
    <<User/binary, "@localhost">> =:= CurUser;
is_current_user(Pid, User) ->
    is_current_user(Pid, iolist_to_binary(User)).
