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

%% @doc MySQL client.
%%
%% The `connection()' type is a gen_server reference as described in the
%% documentation for `gen_server:call/2,3', e.g. the pid or the name if the
%% gen_server is locally registered.
-module(mysql).

-export([start_link/1, query/2, query/3, query/4, execute/3, execute/4,
         prepare/2, prepare/3, unprepare/2,
         warning_count/1, affected_rows/1, autocommit/1, insert_id/1,
         in_transaction/1,
         transaction/2, transaction/3]).

-export_type([connection/0, server_reason/0]).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-define(default_host, "localhost").
-define(default_port, 3306).
-define(default_user, <<>>).
-define(default_password, <<>>).
-define(default_connect_timeout, 5000).
-define(default_query_timeout, infinity).
-define(default_query_cache_time, 60000). %% for query/3.

-define(cmd_timeout, 3000). %% Timeout used for various commands to the server

%% A connection is a ServerRef as in gen_server:call/2,3.
-type connection() :: Name :: atom() |
                      {Name :: atom(), Node :: atom()} |
                      {global, GlobalName :: term()} |
                      {via, Module :: atom(), ViaName :: term()} |
                      pid().

%% MySQL error with the codes and message returned from the server.
-type server_reason() :: {Code :: integer(), SQLState :: binary(),
                          Message :: binary()}.

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
%%   <dt>`{query_timeout, Timeout}'</dt>
%%   <dd>The default time to wait for a response when executing a query or a
%%       prepared statement. This can be given per query using `query/3,4' and
%%       `execute/4'. The default is `infinity'.</dd>
%%   <dt>`{query_cache_time, Timeout}'</dt>
%%   <dd>The minimum number of milliseconds to cache prepared statements used
%%       for parametrized queries with query/3.</dd>
%% </dl>
-spec start_link(Options) -> {ok, pid()} | ignore | {error, term()}
    when Options :: [Option],
         Option :: {name, ServerName} | {host, iodata()} | {port, integer()} | 
                   {user, iodata()} | {password, iodata()} |
                   {database, iodata()} |
                   {connect_timeout, timeout()} |
                   {log_warnings, boolean()} |
                   {query_timeout, timeout()} |
                   {query_cache_time, non_neg_integer()},
         ServerName :: {local, Name :: atom()} |
                       {global, GlobalName :: term()} |
                       {via, Module :: atom(), ViaName :: term()}.
start_link(Options) ->
    GenSrvOpts = [{timeout, proplists:get_value(connect_timeout, Options,
                                                ?default_connect_timeout)}],
    case proplists:get_value(name, Options) of
        undefined ->
            gen_server:start_link(?MODULE, Options, GenSrvOpts);
        ServerName ->
            gen_server:start_link(ServerName, ?MODULE, Options, GenSrvOpts)
    end.

%% @doc Executes a query with the query timeout as given to start_link/1.
-spec query(Conn, Query) -> ok | {ok, ColumnNames, Rows} | {error, Reason}
    when Conn :: connection(),
         Query :: iodata(),
         ColumnNames :: [binary()],
         Rows :: [[term()]],
         Reason :: server_reason().
query(Conn, Query) ->
    gen_server:call(Conn, {query, Query}, infinity).

%% @doc Depending on the 3rd argument this function does different things.
%%
%% If the 3rd argument is a list, it executes a parameterized query. This is
%% equivallent to query/4 with the query timeout as given to start_link/1.
%%
%% If the 3rd argument is a timeout, it executes a plain query with this
%% timeout.
%% @see query/2.
%% @see query/4.
-spec query(Conn, Query, Params | Timeout) -> ok | {ok, ColumnNames, Rows} |
                                              {error, Reason}
    when Conn :: connection(),
         Query :: iodata(),
         Timeout :: timeout(),
         Params :: [term()],
         ColumnNames :: [binary()],
         Rows :: [[term()]],
         Reason :: server_reason().
query(Conn, Query, Params) when is_list(Params) ->
    gen_server:call(Conn, {param_query, Query, Params}, infinity);
query(Conn, Query, Timeout) when is_integer(Timeout); Timeout == infinity ->
    gen_server:call(Conn, {query, Query, Timeout}, infinity).

%% @doc Executes a parameterized query with a timeout.
%%
%% A prepared statement is created, executed and then cached for a certain
%% time. If the same query is executed again when it is already cached, it does
%% not need to be prepared again.
%%
%% The minimum time the prepared statement is cached can be specified using the
%% option `{query_cache_time, Milliseconds}' to start_link/1.
-spec query(Conn, Query, Params, Timeout) -> ok | {ok, ColumnNames, Rows} |
                                             {error, Reason}
    when Conn :: connection(),
         Query :: iodata(),
         Timeout :: timeout(),
         Params :: [term()],
         ColumnNames :: [binary()],
         Rows :: [[term()]],
         Reason :: server_reason().
query(Conn, Query, Params, Timeout) ->
    gen_server:call(Conn, {param_query, Query, Params, Timeout}, infinity).

%% @doc Executes a prepared statement with the default query timeout as given
%% to start_link/1.
%% @see prepare/2
%% @see prepare/3
-spec execute(Conn, StatementRef, Params) ->
    ok | {ok, ColumnNames, Rows} | {error, Reason}
  when Conn :: connection(),
       StatementRef :: atom() | integer(),
       Params :: [term()],
       ColumnNames :: [binary()],
       Rows :: [[term()]],
       Reason :: server_reason() | not_prepared.
execute(Conn, StatementRef, Params) ->
    gen_server:call(Conn, {execute, StatementRef, Params}, infinity).

%% @doc Executes a prepared statement.
%% @see prepare/2
%% @see prepare/3
-spec execute(Conn, StatementRef, Params, Timeout) ->
    ok | {ok, ColumnNames, Rows} | {error, Reason}
  when Conn :: connection(),
       StatementRef :: atom() | integer(),
       Params :: [term()],
       Timeout :: timeout(),
       ColumnNames :: [binary()],
       Rows :: [[term()]],
       Reason :: server_reason() | not_prepared.
execute(Conn, StatementRef, Params, Timeout) ->
    gen_server:call(Conn, {execute, StatementRef, Params, Timeout}, infinity).

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
%% executed query or prepared statement.
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
%% transaction/2,3 or using a plain `mysql:query(Connection, "START
%% TRANSACTION")'.
%% @see transaction/2
%% @see transaction/3
-spec in_transaction(connection()) -> boolean().
in_transaction(Conn) ->
    gen_server:call(Conn, in_transaction).

%% @doc This function executes the functional object Fun as a transaction.
%% @see transaction/3
%% @see in_transaction/1
-spec transaction(connection(), fun()) -> {atomic, term()} | {aborted, term()}.
transaction(Conn, Fun) ->
    transaction(Conn, Fun, []).

%% @doc This function executes the functional object Fun with arguments Args as
%% a transaction. 
%%
%% The semantics are the same as for mnesia's transactions except they are not
%% automatically retried when deadlocks are detected. Transactions can be
%% nested. (MySQL savepoints are used to implement nested transactions.)
%%
%% The Fun must be a function and Args must be a list with the same length
%% as the arity of Fun. 
%%
%% Current limitation: Transactions is not automatically restarted when
%% deadlocks are detected.
%%
%% If an exception occurs within Fun, the exception is caught and `{aborted,
%% Reason}' is returned. The value of `Reason' depends on the class of the
%% exception.
%%
%% Note that an error response from a query does not cause a transaction to be
%% rollbacked. To force a rollback on MySQL errors, you can trigger a `badmatch'
%% using e.g. `ok = mysql:query(Pid, "SELECT some_non_existent_value")'.
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
%%
%% TODO: Automatic restart on deadlocks
%% @see in_transaction/1
-spec transaction(connection(), fun(), list()) -> {atomic, term()} |
                                                  {aborted, term()}.
transaction(Conn, Fun, Args) when is_list(Args),
                                  is_function(Fun, length(Args)) ->
    %% The guard makes sure that we can apply Fun to Args. Any error we catch
    %% in the try-catch are actual errors that occurred in Fun.
    ok = gen_server:call(Conn, start_transaction),
    try apply(Fun, Args) of
        ResultOfFun ->
            %% We must be able to rollback. Otherwise let's crash.
            ok = gen_server:call(Conn, commit),
            {atomic, ResultOfFun}
    catch
        Class:Reason ->
            %% We must be able to rollback. Otherwise let's crash.
            ok = gen_server:call(Conn, rollback),
            %% These forms for throw, error and exit mirror Mnesia's behaviour.
            Aborted = case Class of
                throw -> {throw, Reason};
                error -> {Reason, erlang:get_stacktrace()};
                exit  -> Reason
            end,
            {aborted, Aborted}
    end.

%% --- Gen_server callbacks ---

-include("records.hrl").
-include("server_status.hrl").

%% Gen_server state
-record(state, {server_version, connection_id, socket,
                host, port, user, password, log_warnings,
                query_timeout, query_cache_time,
                affected_rows = 0, status = 0, warning_count = 0, insert_id = 0,
                transaction_level = 0,
                stmts = dict:new(), query_cache = empty}).

%% @private
init(Opts) ->
    %% Connect
    Host     = proplists:get_value(host,          Opts, ?default_host),
    Port     = proplists:get_value(port,          Opts, ?default_port),
    User     = proplists:get_value(user,          Opts, ?default_user),
    Password = proplists:get_value(password,      Opts, ?default_password),
    Database = proplists:get_value(database,      Opts, undefined),
    LogWarn  = proplists:get_value(log_warnings,  Opts, true),
    Timeout  = proplists:get_value(query_timeout, Opts, ?default_query_timeout),
    QueryCacheTime = proplists:get_value(query_cache_time, Opts,
                                         ?default_query_cache_time),

    %% Connect socket
    SockOpts = [{active, false}, binary, {packet, raw}],
    {ok, Socket} = gen_tcp:connect(Host, Port, SockOpts),

    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(User, Password, Database, gen_tcp,
                                      Socket),
    case Result of
        #handshake{server_version = Version, connection_id = ConnId,
                   status = Status} ->
            State = #state{server_version = Version, connection_id = ConnId,
                           socket = Socket,
                           host = Host, port = Port, user = User,
                           password = Password, status = Status,
                           log_warnings = LogWarn,
                           query_timeout = Timeout,
                           query_cache_time = QueryCacheTime},
            %% Trap exit so that we can properly disconnect when we die.
            process_flag(trap_exit, true),
            {ok, State};
        #error{} = E ->
            {stop, error_to_reason(E)}
    end.

%% @private
handle_call({query, Query}, From, State) ->
    handle_call({query, Query, State#state.query_timeout}, From, State);
handle_call({query, Query, Timeout}, _From, State) ->
    Socket = State#state.socket,
    Rec = case mysql_protocol:query(Query, gen_tcp, Socket, Timeout) of
        {error, timeout} when State#state.server_version >= [5, 0, 0] ->
            kill_query(State),
            mysql_protocol:fetch_query_response(gen_tcp, Socket, infinity);
        {error, timeout} ->
            %% For MySQL 4.x.x there is no way to recover from timeout except
            %% killing the connection itself.
            exit(timeout);
        QueryResult ->
            QueryResult
    end,
    State1 = update_state(State, Rec),
    State1#state.warning_count > 0 andalso State1#state.log_warnings
        andalso log_warnings(State1, Query),
    case Rec of
        #ok{} ->
            {reply, ok, State1};
        #error{} = E ->
            {reply, {error, error_to_reason(E)}, State1};
        #resultset{cols = ColDefs, rows = Rows} ->
            Names = [Def#col.name || Def <- ColDefs],
            {reply, {ok, Names, Rows}, State1}
    end;
handle_call({param_query, Query, Params}, From, State) ->
    handle_call({param_query, Query, Params, State#state.query_timeout}, From,
                State);
handle_call({param_query, Query, Params, Timeout}, _From, State) ->
    %% Parametrized query: Prepared statement cached with the query as the key
    QueryBin = iolist_to_binary(Query),
    #state{socket = Socket} = State,
    Cache = State#state.query_cache,
    {StmtResult, Cache1} = case mysql_cache:lookup(QueryBin, Cache) of
        {found, FoundStmt, NewCache} ->
            %% Found
            {{ok, FoundStmt}, NewCache};
        not_found ->
            %% Prepare
            Rec = mysql_protocol:prepare(Query, gen_tcp, Socket),
            %State1 = update_state(State, Rec),
            case Rec of
                #error{} = E ->
                    {{error, error_to_reason(E)}, Cache};
                #prepared{} = Stmt ->
                    %% If the first entry in the cache, start the timer.
                    Cache == empty andalso begin
                        When = State#state.query_cache_time * 2,
                        erlang:send_after(When, self(), query_cache)
                    end,
                    {{ok, Stmt}, mysql_cache:store(QueryBin, Stmt, Cache)}
            end
    end,
    case StmtResult of
        {ok, StmtRec} ->
            State1 = State#state{query_cache = Cache1},
            {Reply, State2} = execute_stmt(StmtRec, Params, Timeout, State1),
            State2#state.warning_count > 0 andalso State2#state.log_warnings
                andalso log_warnings(State2, Query),
            {reply, Reply, State2};
        PrepareError ->
            {reply, PrepareError, State}
    end;
handle_call({execute, Stmt, Args}, From, State) ->
    handle_call({execute, Stmt, Args, State#state.query_timeout}, From, State);
handle_call({execute, Stmt, Args, Timeout}, _From, State) ->
    case dict:find(Stmt, State#state.stmts) of
        {ok, StmtRec} ->
            {Reply, State1} = execute_stmt(StmtRec, Args, Timeout, State),
            State1#state.warning_count > 0 andalso State1#state.log_warnings
                andalso log_warnings(State1,
                                     io_lib:format("prepared statement ~p",
                                                   [Stmt])),
            {reply, Reply, State1};
        error ->
            {reply, {error, not_prepared}, State}
    end;
handle_call({prepare, Query}, _From, State) ->
    #state{socket = Socket} = State,
    Rec = mysql_protocol:prepare(Query, gen_tcp, Socket),
    State1 = update_state(State, Rec),
    case Rec of
        #error{} = E ->
            {reply, {error, error_to_reason(E)}, State1};
        #prepared{statement_id = Id} = Stmt ->
            Stmts1 = dict:store(Id, Stmt, State1#state.stmts),
            State2 = State#state{stmts = Stmts1},
            {reply, {ok, Id}, State2}
    end;
handle_call({prepare, Name, Query}, _From, State) when is_atom(Name) ->
    #state{socket = Socket} = State,
    %% First unprepare if there is an old statement with this name.
    State1 = case dict:find(Name, State#state.stmts) of
        {ok, OldStmt} ->
            mysql_protocol:unprepare(OldStmt, gen_tcp, Socket),
            State#state{stmts = dict:erase(Name, State#state.stmts)};
        error ->
            State
    end,
    Rec = mysql_protocol:prepare(Query, gen_tcp, Socket),
    State2 = update_state(State1, Rec),
    case Rec of
        #error{} = E ->
            {reply, {error, error_to_reason(E)}, State2};
        #prepared{} = Stmt ->
            Stmts1 = dict:store(Name, Stmt, State2#state.stmts),
            State3 = State2#state{stmts = Stmts1},
            {reply, {ok, Name}, State3}
    end;
handle_call({unprepare, Stmt}, _From, State) when is_atom(Stmt);
                                                  is_integer(Stmt) ->
    case dict:find(Stmt, State#state.stmts) of
        {ok, StmtRec} ->
            #state{socket = Socket} = State,
            mysql_protocol:unprepare(StmtRec, gen_tcp, Socket),
            Stmts1 = dict:erase(Stmt, State#state.stmts),
            {reply, ok, State#state{stmts = Stmts1}};
        error ->
            {reply, {error, not_prepared}, State}
    end;
handle_call(warning_count, _From, State) ->
    {reply, State#state.warning_count, State};
handle_call(insert_id, _From, State) ->
    {reply, State#state.insert_id, State};
handle_call(affected_rows, _From, State) ->
    {reply, State#state.affected_rows, State};
handle_call(autocommit, _From, State) ->
    {reply, State#state.status band ?SERVER_STATUS_AUTOCOMMIT /= 0, State};
handle_call(in_transaction, _From, State) ->
    {reply, State#state.status band ?SERVER_STATUS_IN_TRANS /= 0, State};
handle_call(start_transaction, _From,
            State = #state{socket = Socket, transaction_level = L,
                           status = Status})
  when Status band ?SERVER_STATUS_IN_TRANS == 0, L == 0;
       Status band ?SERVER_STATUS_IN_TRANS /= 0, L > 0 ->
    Query = case L of
        0 -> <<"BEGIN">>;
        _ -> <<"SAVEPOINT s", (integer_to_binary(L))/binary>>
    end,
    Res = #ok{} = mysql_protocol:query(Query, gen_tcp, Socket, ?cmd_timeout),
    State1 = update_state(State, Res),
    {reply, ok, State1#state{transaction_level = L + 1}};
handle_call(rollback, _From, State = #state{socket = Socket, status = Status,
                                            transaction_level = L})
  when Status band ?SERVER_STATUS_IN_TRANS /= 0, L >= 1 ->
    Query = case L of
        1 -> <<"ROLLBACK">>;
        _ -> <<"ROLLBACK TO s", (integer_to_binary(L - 1))/binary>>
    end,
    Res = #ok{} = mysql_protocol:query(Query, gen_tcp, Socket, ?cmd_timeout),
    State1 = update_state(State, Res),
    {reply, ok, State1#state{transaction_level = L - 1}};
handle_call(commit, _From, State = #state{socket = Socket, status = Status,
                                          transaction_level = L})
  when Status band ?SERVER_STATUS_IN_TRANS /= 0, L >= 1 ->
    Query = case L of
        1 -> <<"COMMIT">>;
        _ -> <<"RELEASE SAVEPOINT s", (integer_to_binary(L - 1))/binary>>
    end,
    Res = #ok{} = mysql_protocol:query(Query, gen_tcp, Socket, ?cmd_timeout),
    State1 = update_state(State, Res),
    {reply, ok, State1#state{transaction_level = L - 1}};
handle_call(Trans, _From, State) when Trans == start_transaction;
                                      Trans == rollback;
                                      Trans == commit ->
    %% The 'in transaction' flag doesn't match the level we have in the state.
    {reply, {error, incorrectly_nested}, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(query_cache, State = #state{query_cache = Cache,
                                        query_cache_time = CacheTime}) ->
    %% Evict expired queries/statements in the cache used by query/3.
    {Evicted, Cache1} = mysql_cache:evict_older_than(Cache, CacheTime),
    %% Unprepare the evicted statements
    #state{socket = Socket} = State,
    lists:foreach(fun ({_Query, Stmt}) ->
                      mysql_protocol:unprepare(Stmt, gen_tcp, Socket)
                  end,
                  Evicted),
    %% If nonempty, schedule eviction again.
    mysql_cache:size(Cache1) > 0 andalso
        erlang:send_after(CacheTime, self(), query_cache),
    {noreply, State#state{query_cache = Cache1}};
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(Reason, State) when Reason == normal; Reason == shutdown ->
    %% Send the goodbye message for politeness.
    #state{socket = Socket} = State,
    mysql_protocol:quit(gen_tcp, Socket);
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State = #state{}, _Extra) ->
    {ok, State};
code_change(_OldVsn, _State, _Extra) ->
    {error, incompatible_state}.

%% --- Helpers ---

%% @doc Executes a prepared statement and returns {Reply, NextState}.
execute_stmt(Stmt, Args, Timeout, State = #state{socket = Socket}) ->
    Rec = case mysql_protocol:execute(Stmt, Args, gen_tcp, Socket, Timeout) of
        {error, timeout} when State#state.server_version >= [5, 0, 0] ->
            kill_query(State),
            mysql_protocol:fetch_execute_response(gen_tcp, Socket, infinity);
        {error, timeout} ->
            %% For MySQL 4.x.x there is no way to recover from timeout except
            %% killing the connection itself.
            exit(timeout);
        QueryResult ->
            QueryResult
    end,
    State1 = update_state(State, Rec),
    case Rec of
        #ok{} ->
            {ok, State1};
        #error{} = E ->
            {{error, error_to_reason(E)}, State1};
        #resultset{cols = ColDefs, rows = Rows} ->
            Names = [Def#col.name || Def <- ColDefs],
            {{ok, Names, Rows}, State1}
    end.

%% @doc Produces a tuple to return as an error reason.
-spec error_to_reason(#error{}) -> server_reason().
error_to_reason(#error{code = Code, state = State, msg = Msg}) ->
    {Code, State, Msg}.

%% @doc Updates a state with information from a response.
-spec update_state(#state{}, #ok{} | #eof{} | any()) -> #state{}.
update_state(State, #ok{status = S, affected_rows = R,
                        insert_id = Id, warning_count = W}) ->
    State#state{status = S, affected_rows = R, insert_id = Id,
                warning_count = W};
%update_state(State, #eof{status = S, warning_count = W}) ->
%    State#state{status = S, warning_count = W, affected_rows = 0};
update_state(State, #prepared{warning_count = W}) ->
    State#state{warning_count = W};
update_state(State, _Other) ->
    %% This includes errors, resultsets, etc.
    %% Reset warnings, etc. (Note: We don't reset status and insert_id.)
    State#state{warning_count = 0, affected_rows = 0}.

%% @doc Fetches and logs warnings. Query is the query that gave the warnings.
log_warnings(#state{socket = Socket}, Query) ->
    #resultset{rows = Rows} =
        mysql_protocol:query(<<"SHOW WARNINGS">>, gen_tcp, Socket, infinity),
    Lines = [[Level, " ", integer_to_binary(Code), ": ", Message, "\n"]
             || [Level, Code, Message] <- Rows],
    error_logger:warning_msg("~s in ~s~n", [Lines, Query]).

%% @doc Makes a separate connection and execute KILL QUERY. We do this to get
%% our main connection back to normal. KILL QUERY appeared in MySQL 5.0.0.
kill_query(#state{connection_id = ConnId, host = Host, port = Port,
                  user = User, password = Password}) ->
    %% Connect socket
    SockOpts = [{active, false}, binary, {packet, raw}],
    {ok, Socket} = gen_tcp:connect(Host, Port, SockOpts),

    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(User, Password, undefined, gen_tcp,
                                      Socket),
    case Result of
        #handshake{} ->
            %% Kill and disconnect
            IdBin = integer_to_binary(ConnId),
            #ok{} = mysql_protocol:query(<<"KILL QUERY ", IdBin/binary>>,
                                         gen_tcp, Socket, ?cmd_timeout),
            mysql_protocol:quit(gen_tcp, Socket);
        #error{} = E ->
            error_logger:error_msg("Failed to connect to kill query: ~p",
                                   [error_to_reason(E)])
    end.
