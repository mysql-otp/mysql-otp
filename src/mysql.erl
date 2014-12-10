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

-export([start_link/1, query/2, execute/3, prepare/2, prepare/3, unprepare/2,
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
-define(default_timeout, infinity).

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
%% </dl>
-spec start_link(Options) -> {ok, pid()} | ignore | {error, term()}
    when Options :: [Option],
         Option :: {name, ServerName} | {host, iodata()} | {port, integer()} | 
                   {user, iodata()} | {password, iodata()} |
                   {database, iodata()},
         ServerName :: {local, Name :: atom()} |
                       {global, GlobalName :: term()} |
                       {via, Module :: atom(), ViaName :: term()}.
start_link(Options) ->
    case proplists:get_value(name, Options) of
        undefined ->
            gen_server:start_link(?MODULE, Options, []);
        ServerName ->
            gen_server:start_link(ServerName, ?MODULE, Options, [])
    end.

%% @doc Executes a query.
-spec query(Conn, Query) -> ok | {ok, ColumnNames, Rows} | {error, Reason}
    when Conn :: connection(),
         Query :: iodata(),
         ColumnNames :: [binary()],
         Rows :: [[term()]],
         Reason :: server_reason().
query(Conn, Query) ->
    gen_server:call(Conn, {query, Query}).

%% @doc Executes a prepared statement.
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
    gen_server:call(Conn, {execute, StatementRef, Params}).

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
%% The semantics are the same as for mnesia's transactions.
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
%% If an exception occurs within Fun, the exception is caught and `{aborted,
%% Reason}' is returned. The value of `Reason' depends on the class of the
%% exception.
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
%% TODO: Implement nested transactions
%% TODO: Automatic restart on deadlocks
%% @see in_transaction/1
-spec transaction(connection(), fun(), list()) -> {atomic, term()} |
                                                  {aborted, term()}.
transaction(Conn, Fun, Args) when is_list(Args),
                                  is_function(Fun, length(Args)) ->
    %% The guard makes sure that we can apply Fun to Args. Any error we catch
    %% in the try-catch are actual errors that occurred in Fun.
    ok = query(Conn, <<"BEGIN">>),
    try apply(Fun, Args) of
        ResultOfFun ->
            %% We must be able to rollback. Otherwise let's crash.
            ok = query(Conn, <<"COMMIT">>),
            {atomic, ResultOfFun}
    catch
        Class:Reason ->
            %% We must be able to rollback. Otherwise let's crash.
            ok = query(Conn, <<"ROLLBACK">>),
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
-record(state, {socket, timeout = infinity, affected_rows = 0, status = 0,
                warning_count = 0, insert_id = 0, stmts = dict:new()}).

%% @private
init(Opts) ->
    %% Connect
    Host     = proplists:get_value(host,     Opts, ?default_host),
    Port     = proplists:get_value(port,     Opts, ?default_port),
    User     = proplists:get_value(user,     Opts, ?default_user),
    Password = proplists:get_value(password, Opts, ?default_password),
    Database = proplists:get_value(database, Opts, undefined),
    Timeout  = proplists:get_value(timeout,  Opts, ?default_timeout),

    %% Connect socket
    SockOpts = [{active, false}, binary, {packet, raw}],
    {ok, Socket} = gen_tcp:connect(Host, Port, SockOpts),

    %% Exchange handshake communication.
    SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
    RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
    Result = mysql_protocol:handshake(User, Password, Database, SendFun,
                                      RecvFun),
    case Result of
        #ok{} = OK ->
            State = #state{socket = Socket, timeout = Timeout},
            State1 = update_state(State, OK),
            %% Trap exit so that we can properly disconnect when we die.
            process_flag(trap_exit, true),
            {ok, State1};
        #error{} = E ->
            {stop, error_to_reason(E)}
    end.

%% @private
handle_call({query, Query}, _From, State) when is_binary(Query);
                                               is_list(Query) ->
    #state{socket = Socket, timeout = Timeout} = State,
    SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
    RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
    Rec = mysql_protocol:query(Query, SendFun, RecvFun),
    State1 = update_state(State, Rec),
    case Rec of
        #ok{} ->
            {reply, ok, State1};
        #error{} = E ->
            {reply, {error, error_to_reason(E)}, State1};
        #resultset{cols = ColDefs, rows = Rows} ->
            Names = [Def#col.name || Def <- ColDefs],
            {reply, {ok, Names, Rows}, State1}
    end;
handle_call({execute, Stmt, Args}, _From, State) when is_atom(Stmt);
                                                      is_integer(Stmt) ->
    case dict:find(Stmt, State#state.stmts) of
        {ok, StmtRec} ->
            #state{socket = Socket, timeout = Timeout} = State,
            SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
            RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
            Rec = mysql_protocol:execute(StmtRec, Args, SendFun, RecvFun),
            State1 = update_state(State, Rec),
            case Rec of
                #ok{} ->
                    {reply, ok, State1};
                #error{} = E ->
                    {reply, {error, error_to_reason(E)}, State1};
                #resultset{cols = ColDefs, rows = Rows} ->
                    Names = [Def#col.name || Def <- ColDefs],
                    {reply, {ok, Names, Rows}, State1}
            end;
        error ->
            {reply, {error, not_prepared}, State}
    end;
handle_call({prepare, Query}, _From, State) ->
    #state{socket = Socket, timeout = Timeout} = State,
    SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
    RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
    Rec = mysql_protocol:prepare(Query, SendFun, RecvFun),
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
    #state{socket = Socket, timeout = Timeout} = State,
    SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
    RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
    %% First unprepare if there is an old statement with this name.
    State1 = case dict:find(Name, State#state.stmts) of
        {ok, OldStmt} ->
            mysql_protocol:unprepare(OldStmt, SendFun, RecvFun),
            State#state{stmts = dict:erase(Name, State#state.stmts)};
        error ->
            State
    end,
    Rec = mysql_protocol:prepare(Query, SendFun, RecvFun),
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
            #state{socket = Socket, timeout = Timeout} = State,
            SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
            RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
            mysql_protocol:unprepare(StmtRec, SendFun, RecvFun),
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
    {reply, State#state.status band ?SERVER_STATUS_IN_TRANS /= 0, State}.

%% @private
handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(Reason, State) when Reason == normal; Reason == shutdown ->
    %% Send the goodbye message for politeness.
    #state{socket = Socket, timeout = Timeout} = State,
    SendFun = fun (Data) -> gen_tcp:send(Socket, Data) end,
    RecvFun = fun (Size) -> gen_tcp:recv(Socket, Size, Timeout) end,
    mysql_protocol:quit(SendFun, RecvFun);
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State = #state{}, _Extra) ->
    {ok, State};
code_change(_OldVsn, _State, _Extra) ->
    {error, incompatible_state}.

%% --- Helpers ---

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
