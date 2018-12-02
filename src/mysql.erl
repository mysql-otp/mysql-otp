%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014-2015, 2018 Viktor Söderqvist,
%%               2016 Johan Lövdahl
%%               2017 Piotr Nosek, Michal Slaski
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

%% @doc MySQL client.
%%
%% The `connection()' type is a gen_server reference as described in the
%% documentation for `gen_server:call/2,3', e.g. the pid or the name if the
%% gen_server is locally registered.
-module(mysql).

-export([start_link/1, query/2, query/3, query/4, execute/3, execute/4,
         prepare/2, prepare/3, unprepare/2,
         warning_count/1, affected_rows/1, autocommit/1, insert_id/1,
         encode/2, in_transaction/1,
         transaction/2, transaction/3, transaction/4]).

-export_type([connection/0, server_reason/0, query_result/0]).

%% A connection is a ServerRef as in gen_server:call/2,3.
-type connection() :: Name :: atom() |
                      {Name :: atom(), Node :: atom()} |
                      {global, GlobalName :: term()} |
                      {via, Module :: atom(), ViaName :: term()} |
                      pid().

%% MySQL error with the codes and message returned from the server.
-type server_reason() :: {Code :: integer(), SQLState :: binary() | undefined,
                          Message :: binary()}.

-type column_names() :: [binary()].
-type rows() :: [[term()]].

-type query_result() :: ok
                      | {ok, column_names(), rows()}
                      | {ok, [{column_names(), rows()}, ...]}
                      | {error, server_reason()}.

-define(default_connect_timeout, 5000).

-include("exception.hrl").

%% @doc Starts a connection gen_server process and connects to a database. To
%% disconnect just do `exit(Pid, normal)'.
%%
%% Options:
%%
%% <dl>
%%   <dt>`{name, ServerName}'</dt>
%%   <dd>If a name is provided, the gen_server will be registered with this
%%       name. For details see the documentation for the first argument of
%%       gen_server:start_link/4.</dd>
%%   <dt>`{host, Host}'</dt>
%%   <dd>Hostname of the MySQL database; default `"localhost"'.</dd>
%%   <dt>`{port, Port}'</dt>
%%   <dd>Port; default 3306 if omitted.</dd>
%%   <dt>`{user, User}'</dt>
%%   <dd>Username.</dd>
%%   <dt>`{password, Password}'</dt>
%%   <dd>Password.</dd>
%%   <dt>`{database, Database}'</dt>
%%   <dd>The name of the database AKA schema to use. This can be changed later
%%       using the query `USE <database>'.</dd>
%%   <dt>`{connect_timeout, Timeout}'</dt>
%%   <dd>The maximum time to spend for start_link/1.</dd>
%%   <dt>`{log_warnings, boolean()}'</dt>
%%   <dd>Whether to fetch warnings and log them using error_logger; default
%%       true.</dd>
%%   <dt>`{keep_alive, boolean() | timeout()}'</dt>
%%   <dd>Send ping when unused for a certain time. Possible values are `true',
%%       `false' and `integer() > 0' for an explicit interval in milliseconds.
%%       The default is `false'. For `true' a default ping timeout is used.
%%       </dd>
%%   <dt>`{prepare, NamedStatements}'</dt>
%%   <dd>Named prepared statements to be created as soon as the connection is
%%       ready.</dd>
%%   <dt>`{queries, Queries}'</dt>
%%   <dd>Queries to be executed as soon as the connection is ready. Any results
%%       are discarded. Typically, this is used for setting time zone and other
%%       session variables.</dd>
%%   <dt>`{query_timeout, Timeout}'</dt>
%%   <dd>The default time to wait for a response when executing a query or a
%%       prepared statement. This can be given per query using `query/3,4' and
%%       `execute/4'. The default is `infinity'.</dd>
%%   <dt>`{found_rows, boolean()}'</dt>
%%   <dd>If set to true, the connection will be established with
%%       CLIENT_FOUND_ROWS capability. affected_rows/1 will now return the
%%       number of found rows, not the number of rows changed by the
%%       query.</dd>
%%   <dt>`{query_cache_time, Timeout}'</dt>
%%   <dd>The minimum number of milliseconds to cache prepared statements used
%%       for parametrized queries with query/3.</dd>
%%   <dt>`{tcp_options, Options}'</dt>
%%   <dd>Additional options for `gen_tcp:connect/3'. You may want to set
%%       `{recbuf, Size}' and `{sndbuf, Size}' if you send or receive more than
%%       the default (typically 8K) per query.</dd>
%% </dl>
-spec start_link(Options) -> {ok, pid()} | ignore | {error, term()}
    when Options :: [Option],
         Option :: {name, ServerName} |
                   {host, inet:socket_address() | inet:hostname()} | {port, integer()} |
                   {user, iodata()} | {password, iodata()} |
                   {database, iodata()} |
                   {connect_timeout, timeout()} |
                   {log_warnings, boolean()} |
                   {keep_alive, boolean() | timeout()} |
                   {prepare, NamedStatements} |
                   {queries, [iodata()]} |
                   {query_timeout, timeout()} |
                   {found_rows, boolean()} |
                   {query_cache_time, non_neg_integer()},
         ServerName :: {local, Name :: atom()} |
                       {global, GlobalName :: term()} |
                       {via, Module :: atom(), ViaName :: term()},
         NamedStatements :: [{StatementName :: atom(), Statement :: iodata()}].
start_link(Options) ->
    GenSrvOpts = [{timeout, proplists:get_value(connect_timeout, Options,
                                                ?default_connect_timeout)}],
    Ret = case proplists:get_value(name, Options) of
        undefined ->
            gen_server:start_link(mysql_conn, Options, GenSrvOpts);
        ServerName ->
            gen_server:start_link(ServerName, mysql_conn, Options, GenSrvOpts)
    end,
    case Ret of
        {ok, Pid} ->
            %% Initial queries
            Queries = proplists:get_value(queries, Options, []),
            lists:foreach(fun (Query) ->
                              case mysql:query(Pid, Query) of
                                  ok -> ok;
                                  {ok, _, _} -> ok;
                                  {ok, _} -> ok
                              end
                          end,
                          Queries),
            %% Prepare
            Prepare = proplists:get_value(prepare, Options, []),
            lists:foreach(fun ({Name, Stmt}) ->
                              {ok, Name} = mysql:prepare(Pid, Name, Stmt)
                          end,
                          Prepare);
        _ -> ok
    end,
    Ret.

%% @doc Executes a query with the query timeout as given to start_link/1.
%%
%% It is possible to execute multiple semicolon-separated queries.
%%
%% Results are returned in the form `{ok, ColumnNames, Rows}' if there is one
%% result set. If there are more than one result sets, they are returned in the
%% form `{ok, [{ColumnNames, Rows}, ...]}'.
%%
%% For queries that don't return any rows (INSERT, UPDATE, etc.) only the atom
%% `ok' is returned.
-spec query(Conn, Query) -> Result
    when Conn :: connection(),
         Query :: iodata(),
         Result :: query_result().
query(Conn, Query) ->
    query_call(Conn, {query, Query}).

%% @doc Depending on the 3rd argument this function does different things.
%%
%% If the 3rd argument is a list, it executes a parameterized query. This is
%% equivallent to query/4 with the query timeout as given to start_link/1.
%%
%% If the 3rd argument is a timeout, it executes a plain query with this
%% timeout.
%%
%% The return value is the same as for query/2.
%%
%% @see query/2.
%% @see query/4.
-spec query(Conn, Query, Params | Timeout) -> Result
    when Conn :: connection(),
         Query :: iodata(),
         Timeout :: timeout(),
         Params :: [term()],
         Result :: query_result().
query(Conn, Query, Params) when is_list(Params) ->
    query_call(Conn, {param_query, Query, Params});
query(Conn, Query, Timeout) when is_integer(Timeout); Timeout == infinity ->
    query_call(Conn, {query, Query, Timeout}).

%% @doc Executes a parameterized query with a timeout.
%%
%% A prepared statement is created, executed and then cached for a certain
%% time. If the same query is executed again when it is already cached, it does
%% not need to be prepared again.
%%
%% The minimum time the prepared statement is cached can be specified using the
%% option `{query_cache_time, Milliseconds}' to start_link/1.
%%
%% The return value is the same as for query/2.
-spec query(Conn, Query, Params, Timeout) -> Result
    when Conn :: connection(),
         Query :: iodata(),
         Timeout :: timeout(),
         Params :: [term()],
         Result :: query_result().
query(Conn, Query, Params, Timeout) ->
    query_call(Conn, {param_query, Query, Params, Timeout}).

%% @doc Executes a prepared statement with the default query timeout as given
%% to start_link/1.
%% @see prepare/2
%% @see prepare/3
-spec execute(Conn, StatementRef, Params) -> Result | {error, not_prepared}
  when Conn :: connection(),
       StatementRef :: atom() | integer(),
       Params :: [term()],
       Result :: query_result().
execute(Conn, StatementRef, Params) ->
    query_call(Conn, {execute, StatementRef, Params}).

%% @doc Executes a prepared statement.
%% @see prepare/2
%% @see prepare/3
-spec execute(Conn, StatementRef, Params, Timeout) ->
    Result | {error, not_prepared}
  when Conn :: connection(),
       StatementRef :: atom() | integer(),
       Params :: [term()],
       Timeout :: timeout(),
       Result :: query_result().
execute(Conn, StatementRef, Params, Timeout) ->
    query_call(Conn, {execute, StatementRef, Params, Timeout}).

%% @doc Creates a prepared statement from the passed query.
%% @see prepare/3
-spec prepare(Conn, Query) -> {ok, StatementId} | {error, Reason}
  when Conn :: connection(),
       Query :: iodata(),
       StatementId :: integer(),
       Reason :: server_reason().
prepare(Conn, Query) ->
    gen_server:call(Conn, {prepare, Query}).

%% @doc Creates a prepared statement from the passed query and associates it
%% with the given name.
%% @see prepare/2
-spec prepare(Conn, Name, Query) -> {ok, Name} | {error, Reason}
  when Conn :: connection(),
       Name :: atom(),
       Query :: iodata(),
       Reason :: server_reason().
prepare(Conn, Name, Query) ->
    gen_server:call(Conn, {prepare, Name, Query}).

%% @doc Deallocates a prepared statement.
-spec unprepare(Conn, StatementRef) -> ok | {error, Reason}
  when Conn :: connection(),
       StatementRef :: atom() | integer(),
       Reason :: server_reason() | not_prepared.
unprepare(Conn, StatementRef) ->
    gen_server:call(Conn, {unprepare, StatementRef}).

%% @doc Returns the number of warnings generated by the last query/2 or
%% execute/3 calls.
-spec warning_count(connection()) -> integer().
warning_count(Conn) ->
    gen_server:call(Conn, warning_count).

%% @doc Returns the number of inserted, updated and deleted rows of the last
%% executed query or prepared statement. If found_rows is set on the
%% connection, for update operation the return value will equal to the number
%% of rows matched by the query.
-spec affected_rows(connection()) -> integer().
affected_rows(Conn) ->
    gen_server:call(Conn, affected_rows).

%% @doc Returns true if auto-commit is enabled and false otherwise.
-spec autocommit(connection()) -> boolean().
autocommit(Conn) ->
    gen_server:call(Conn, autocommit).

%% @doc Returns the last insert-id.
-spec insert_id(connection()) -> integer().
insert_id(Conn) ->
    gen_server:call(Conn, insert_id).

%% @doc Returns true if the connection is in a transaction and false otherwise.
%% This works regardless of whether the transaction has been started using
%% transaction/2,3 or using a plain `mysql:query(Connection, "BEGIN")'.
%% @see transaction/2
%% @see transaction/4
-spec in_transaction(connection()) -> boolean().
in_transaction(Conn) ->
    gen_server:call(Conn, in_transaction).

%% @doc This function executes the functional object Fun as a transaction.
%% @see transaction/4
-spec transaction(connection(), fun()) -> {atomic, term()} | {aborted, term()}.
transaction(Conn, Fun) ->
    transaction(Conn, Fun, [], infinity).

%% @doc This function executes the functional object Fun as a transaction.
%% @see transaction/4
-spec transaction(connection(), fun(), Retries) -> {atomic, term()} |
                                                   {aborted, term()}
    when Retries :: non_neg_integer() | infinity.
transaction(Conn, Fun, Retries) ->
    transaction(Conn, Fun, [], Retries).

%% @doc This function executes the functional object Fun with arguments Args as
%% a transaction.
%%
%% The semantics are as close as possible to mnesia's transactions. Transactions
%% can be nested and are restarted automatically when deadlocks are detected.
%% MySQL's savepoints are used to implement nested transactions.
%%
%% Fun must be a function and Args must be a list of the same length as the
%% arity of Fun.
%%
%% If an exception occurs within Fun, the exception is caught and `{aborted,
%% Reason}' is returned. The value of `Reason' depends on the class of the
%% exception.
%%
%% Note that an error response from a query does not cause a transaction to be
%% rollbacked. To force a rollback on a MySQL error you can trigger a `badmatch'
%% using e.g. `ok = mysql:query(Pid, "SELECT some_non_existent_value")'. An
%% exception to this is the error 1213 "Deadlock", after the specified number
%% of retries, all failed. In this case, the transaction is aborted and the
%% error is retured as the reason for the aborted transaction, along with a
%% stacktrace pointing to where the last deadlock was detected. (In earlier
%% versions, up to and including 1.3.2, transactions where automatically
%% restarted also for the error 1205 "Lock wait timeout". This is no longer the
%% case.)
%%
%% Some queries such as ALTER TABLE cause an *implicit commit* on the server.
%% If such a query is executed within a transaction, an error on the form
%% `{implicit_commit, Query}' is raised. This means that the transaction has
%% been committed prematurely. This also happens if an explicit COMMIT is
%% executed as a plain query within a managed transaction. (Don't do that!)
%%
%% <table>
%%   <thead>
%%     <tr><th>Class of exception</th><th>Return value</th></tr>
%%   </thead>
%%   <tbody>
%%     <tr>
%%       <td>`error' with reason `ErrorReason'</td>
%%       <td>`{aborted, {ErrorReason, Stack}}'</td>
%%     </tr>
%%     <tr><td>`exit(Term)'</td><td>`{aborted, Term}'</td></tr>
%%     <tr><td>`throw(Term)'</td><td>`{aborted, {throw, Term}}'</td></tr>
%%   </tbody>
%% </table>
-spec transaction(connection(), fun(), list(), Retries) -> {atomic, term()} |
                                                           {aborted, term()}
    when Retries :: non_neg_integer() | infinity.
transaction(Conn, Fun, Args, Retries) when is_list(Args),
                                           is_function(Fun, length(Args)) ->
    %% The guard makes sure that we can apply Fun to Args. Any error we catch
    %% in the try-catch are actual errors that occurred in Fun.
    ok = gen_server:call(Conn, start_transaction, infinity),
    execute_transaction(Conn, Fun, Args, Retries).

%% @private
%% @doc This is a helper for transaction/2,3,4. It performs everything except
%% executing the BEGIN statement. It is called recursively when a transaction
%% is retried.
%%
%% "When a transaction rollback occurs due to a deadlock or lock wait timeout,
%% it cancels the effect of the statements within the transaction. But if the
%% start-transaction statement was START TRANSACTION or BEGIN statement,
%% rollback does not cancel that statement."
%% (https://dev.mysql.com/doc/refman/5.6/en/innodb-error-handling.html)
%%
%% Lock Wait Timeout:
%% "InnoDB rolls back only the last statement on a transaction timeout by
%% default. If --innodb_rollback_on_timeout is specified, a transaction timeout
%% causes InnoDB to abort and roll back the entire transaction (the same
%% behavior as in MySQL 4.1)."
%% (https://dev.mysql.com/doc/refman/5.6/en/innodb-parameters.html)
execute_transaction(Conn, Fun, Args, Retries) ->
    try apply(Fun, Args) of
        ResultOfFun ->
            ok = gen_server:call(Conn, commit, infinity),
            {atomic, ResultOfFun}
    catch
        %% We are at the top level, try to restart the transaction if there are
        %% retries left
        ?EXCEPTION(throw, {implicit_rollback, 1, _}, _Stacktrace)
          when Retries == infinity ->
            execute_transaction(Conn, Fun, Args, infinity);
        ?EXCEPTION(throw, {implicit_rollback, 1, _}, _Stacktrace)
          when Retries > 0 ->
            execute_transaction(Conn, Fun, Args, Retries - 1);
        ?EXCEPTION(throw, {implicit_rollback, 1, Reason}, Stacktrace)
          when Retries == 0 ->
            %% No more retries. Return 'aborted' along with the deadlock error
            %% and a the trace to the line where the deadlock occured.
            Trace = ?GET_STACK(Stacktrace),
            ok = gen_server:call(Conn, rollback, infinity),
            {aborted, {Reason, Trace}};
        ?EXCEPTION(throw, {implicit_rollback, N, Reason}, Stacktrace)
          when N > 1 ->
            %% Nested transaction. Bubble out to the outermost level.
            erlang:raise(throw, {implicit_rollback, N - 1, Reason},
                         ?GET_STACK(Stacktrace));
        ?EXCEPTION(error, {implicit_commit, _Query} = E, Stacktrace) ->
            %% The called did something like ALTER TABLE which resulted in an
            %% implicit commit. The server has already committed. We need to
            %% jump out of N levels of transactions.
            %%
            %% Returning 'atomic' or 'aborted' would both be wrong. Raise an
            %% exception is the best we can do.
            erlang:raise(error, E, ?GET_STACK(Stacktrace));
        ?EXCEPTION(Class, Reason, Stacktrace) ->
            %% We must be able to rollback. Otherwise let's crash.
            ok = gen_server:call(Conn, rollback, infinity),
            %% These forms for throw, error and exit mirror Mnesia's behaviour.
            Aborted = case Class of
                throw -> {throw, Reason};
                error -> {Reason, ?GET_STACK(Stacktrace)};
                exit  -> Reason
            end,
            {aborted, Aborted}
    end.

%% @doc Encodes a term as a MySQL literal so that it can be used to inside a
%% query. If backslash escapes are enabled, backslashes and single quotes in
%% strings and binaries are escaped. Otherwise only single quotes are escaped.
%%
%% Note that the preferred way of sending values is by prepared statements or
%% parametrized queries with placeholders.
%%
%% @see query/3
%% @see execute/3
-spec encode(connection(), term()) -> iodata().
encode(Conn, Term) ->
    Term1 = case (is_list(Term) orelse is_binary(Term)) andalso
                 gen_server:call(Conn, backslash_escapes_enabled) of
        true  -> mysql_encode:backslash_escape(Term);
        false -> Term
    end,
    mysql_encode:encode(Term1).

%% --- Helpers ---

%% @doc Makes a gen_server call for a query (plain, parametrized or prepared),
%% checks the reply and sometimes throws an exception when we need to jump out
%% of a transaction.
query_call(Conn, CallReq) ->
    case gen_server:call(Conn, CallReq, infinity) of
        {implicit_commit, _NestingLevel, Query} ->
            error({implicit_commit, Query});
        {implicit_rollback, _NestingLevel, _ServerReason} = ImplicitRollback ->
            throw(ImplicitRollback);
        Result ->
            Result
    end.


