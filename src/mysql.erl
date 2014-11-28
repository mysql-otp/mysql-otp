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
         affected_rows/1, insert_id/1]).

%% MySQL error with the codes and message returned from the server.
-type reason() :: {Code :: integer(), SQLState :: binary(),
                   Message :: binary()}.

%% @doc Starts a connection process and connects to a database. To disconnect
%% do `exit(Pid, normal)'.
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
