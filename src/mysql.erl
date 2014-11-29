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

%% @doc MySQL/OTP. FIXME: Documentation of value representation, examples
%% and more.
%%
%% This documentation is written with `edoc' as part of the source code and thus
%% is covered by GPL 3 or later. See the LICENSE file or find GPL 3 on
%% <a href="http://www.gnu.org/licenses/">http://www.gnu.org/licenses/</a>.
-module(mysql).

-export([start_link/1, query/2, execute/3, prepare/2, warning_count/1,
         affected_rows/1, insert_id/1, transaction/2, transaction/3]).

%% MySQL error with the codes and message returned from the server.
-type reason() :: {Code :: integer(), SQLState :: binary(),
                   Message :: binary()}.

%% @doc Starts a connection process and connects to a database. To disconnect
%% do `exit(Pid, normal)'.
%%
%% This is just a wrapper for `gen_server:start_link(mysql_connection, Options,
%% [])'. If you need to specify gen_server options, use gen_server:start_link/3
%% directly.
-spec start_link(Options) -> {ok, pid()} | ignore | {error, term()}
    when Options :: [Option],
         Option :: {host, iodata()} | {port, integer()} | {user, iodata()} |
                   {password, iodata()} | {database, iodata()}.
start_link(Opts) ->
    gen_server:start_link(mysql_connection, Opts, []).

-spec query(Conn, Query) -> ok | {ok, Fields, Rows} | {error, Reason}
    when Conn :: pid(),
         Query :: iodata(),
         Fields :: [binary()],
         Rows :: [[term()]],
         Reason :: reason().
query(Conn, Query) ->
    gen_server:call(Conn, {query, Query}).

%% @doc Executes a prepared statement.
execute(Conn, StatementId, Args) ->
    gen_server:call(Conn, {execute, StatementId, Args}).

-spec prepare(Conn :: pid(), Query :: iodata()) ->
    {ok, StatementId :: integer()} | {error, Reason :: reason()}.
prepare(Conn, Query) ->
    gen_server:call(Conn, {prepare, Query}).

-spec warning_count(pid()) -> integer().
warning_count(Conn) ->
    gen_server:call(Conn, warning_count).

-spec affected_rows(pid()) -> integer().
affected_rows(Conn) ->
    gen_server:call(Conn, affected_rows).

-spec insert_id(pid()) -> integer().
insert_id(Conn) ->
    gen_server:call(Conn, insert_id).

%% @doc This function executes the functional object Fun as a transaction.
%% @see transaction/2
-spec transaction(pid(), fun()) -> {atomic, term()} | {aborted, term()}.
transaction(Conn, Fun) ->
    transaction(Conn, Fun, []).

%% @doc This function executes the functional object Fun with arguments Args as
%% a transaction. 
%%
%% The semantics are the sames as for mnesia's transactions.
%%
%% The Fun must be a function and Args must be a list with the same length
%% as the arity of Fun. 
%%
%% Current limitations:
%%
%% <ul>
%%   <li>Transactions cannot be nested</li>
%%   <li>They are not automatically restarted when deadlocks are detected.</li>
%% </ul>
%%
%% TODO: Implement nested transactions
%% TODO: Automatic restart on deadlocks
-spec transaction(pid(), fun(), list()) -> {atomic, term()} | {aborted, term()}.
transaction(Conn, Fun, Args) when is_list(Args),
                                  is_function(Fun, length(Args)) ->
    %% The guard makes sure that we can apply Fun to Args. Any error we catch
    %% in the try-catch are actual errors that occurred in Fun.
    ok = query(Conn, <<"BEGIN">>),
    try apply(Fun, Args) of
        ResultOfFun ->
            %% We must be able to rollback. Otherwise let's go mad.
            ok = query(Conn, <<"COMMIT">>),
            {atomic, ResultOfFun}
    catch
        Class:Reason ->
            %% We must be able to rollback. Otherwise let's go mad.
            ok = query(Conn, <<"ROLLBACK">>),
            %% These forms for throw, error and exit mirror Mnesia's behaviour.
            Aborted = case Class of
                throw -> {throw, Reason};
                error -> {Reason, erlang:get_stacktrace()};
                exit  -> Reason
            end,
            {aborted, Aborted}
    end.
