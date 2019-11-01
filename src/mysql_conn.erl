%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014-2018 Viktor Söderqvist
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

%% @doc This module implements parts of the MySQL client/server protocol.
%%
%% The protocol is described in the document "MySQL Internals" which can be
%% found under "MySQL Documentation: Expert Guides" on http://dev.mysql.com/.
%%
%% TCP communication is not handled in this module. Most of the public functions
%% take funs for data communitaction as parameters.
%% @private
-module(mysql_conn).

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-define(default_host, "localhost").
-define(default_port, 3306).
-define(default_user, <<>>).
-define(default_password, <<>>).
-define(default_query_timeout, infinity).
-define(default_query_cache_time, 60000). %% for query/3.
-define(default_ping_timeout, 60000).

-define(cmd_timeout, 3000). %% Timeout used for various commands to the server

-define(reconnect_interval, 100). %% Try to reconnect to server every 100 ms
-define(reconnect_timeout,  10000). %% Do not reconnect after 10 s, infinity means reconnect for ever.

%% Errors that cause "implicit rollback"
-define(ERROR_DEADLOCK, 1213).

%% --- Gen_server callbacks ---

-include("records.hrl").
-include("server_status.hrl").

%% Gen_server state
-record(state, {server_version, connection_id, socket, sockmod, ssl_opts,
                host, port, user, password, auth_plugin_data, log_warnings,
                ping_timeout,
                query_timeout, query_cache_time,
                affected_rows = 0, status = 0, warning_count = 0, insert_id = 0,
                transaction_levels = [], ping_ref = undefined,
                stmts = dict:new(), query_cache = empty, cap_found_rows = false,
                queries, prepare,
                database, socket_opts,
                reconnect_pid, reconnect_interval, reconnect_timeout}).

%% @private
init(Opts) ->
    %% Connect
    Host           = proplists:get_value(host, Opts, ?default_host),

    DefaultPort = case Host of
        {local, _LocalAddr} -> 0;
        _NonLocalAddr -> ?default_port
    end,
    Port           = proplists:get_value(port, Opts, DefaultPort),

    User           = proplists:get_value(user, Opts, ?default_user),
    Password       = proplists:get_value(password, Opts, ?default_password),
    Database       = proplists:get_value(database, Opts, undefined),
    LogWarn        = proplists:get_value(log_warnings, Opts, true),
    KeepAlive      = proplists:get_value(keep_alive, Opts, false),
    Timeout        = proplists:get_value(query_timeout, Opts,
                                         ?default_query_timeout),
    QueryCacheTime = proplists:get_value(query_cache_time, Opts,
                                         ?default_query_cache_time),
    TcpOpts        = proplists:get_value(tcp_options, Opts, []),
    SetFoundRows   = proplists:get_value(found_rows, Opts, false),
    SSLOpts        = proplists:get_value(ssl, Opts, undefined),
    SockMod0       = gen_tcp,

    Queries        = proplists:get_value(queries, Opts, []),
    Prepares       = proplists:get_value(prepare, Opts, []),

    ReconnectTimeout  = proplists:get_value(reconnect_timeout, Opts, undefined),
    ReconnectInterval = proplists:get_value(reconnect_interval,
                                            Opts,
                                            reconnect_interval(ReconnectTimeout)),

    PingTimeout = case KeepAlive of
        true         -> ?default_ping_timeout;
        false        -> infinity;
        N when N > 0 -> N
    end,

    %% Connect socket
    SockOpts = [binary, {packet, raw}, {active, false}, {nodelay, true}
                | TcpOpts],
    {ok, Socket0} = SockMod0:connect(Host, Port, SockOpts),

    %% If buffer wasn't specifically defined make it at least as
    %% large as recbuf, as suggested by the inet:setopts() docs.
    case proplists:is_defined(buffer, TcpOpts) of
        true ->
            ok;
        false ->
            {ok, [{buffer, Buffer}]} = inet:getopts(Socket0, [buffer]),
            {ok, [{recbuf, Recbuf}]} = inet:getopts(Socket0, [recbuf]),
            ok = inet:setopts(Socket0,[{buffer, max(Buffer, Recbuf)}])
    end,

    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(User, Password, Database, SockMod0, SSLOpts,
                                      Socket0, SetFoundRows),
    case Result of
        {ok, Handshake, SockMod, Socket} ->
            setopts(SockMod, Socket, [{active, once}]),
            #handshake{server_version = Version, connection_id = ConnId,
                       status = Status,
                       auth_plugin_data = AuthPluginData} = Handshake,
            State = #state{server_version = Version, connection_id = ConnId,
                           database = Database, queries = Queries, prepare = Prepares,
                           sockmod = SockMod,
                           socket = Socket,
                           ssl_opts = SSLOpts,
                           host = Host, port = Port,
                           user = User, password = Password,
                           auth_plugin_data = AuthPluginData,
                           status = Status,
                           log_warnings = LogWarn,
                           ping_timeout = PingTimeout,
                           query_timeout = Timeout,
                           query_cache_time = QueryCacheTime,
                           cap_found_rows = (SetFoundRows =:= true),
                           socket_opts = SockOpts,
                           reconnect_interval = ReconnectInterval,
                           reconnect_timeout = seconds(ReconnectTimeout)},
            case execute_on_connect(Queries, Prepares, State) of
                {ok, State1} ->
                    process_flag(trap_exit, true),
                    State2 = schedule_ping(State1),
                    {ok, State2};
                {error, Reason} ->
                    {stop, Reason}
            end;
        #error{} = E ->
            {stop, error_to_reason(E)}
    end.

execute_on_connect([], [], State) ->
    {ok, State};
execute_on_connect([], [{Name, Stmt}|Prepares], State) ->
    case do_named_prepare(Name, Stmt, State) of
        {{ok, Name}, State1} ->
            execute_on_connect([], Prepares, State1);
        {{error, _} = E, _} ->
            E
    end;
execute_on_connect([Query|Queries], Prepares, State) ->
    case do_query(Query, no_filtermap_fun, default_timeout, State) of
        {ok, State1} ->
            execute_on_connect(Queries, Prepares, State1);
        {{ok, _}, State1} ->
            execute_on_connect(Queries, Prepares, State1);
        {{ok, _, _}, State1} ->
            execute_on_connect(Queries, Prepares, State1);
        {{error, _} = E, _} ->
            E
    end.

%% @private
%% @doc
%%
%% Query and execute calls:
%%
%% <ul>
%%   <li>{query, Query, FilterMap, Timeout}</li>
%%   <li>{param_query, Query, Params, FilterMap, Timeout}</li>
%%   <li>{execute, Stmt, Args, FilterMap, Timeout}</li>
%% </ul>
%%
%% For the calls listed above, we return these values:
%%
%% <dl>
%%   <dt>`ok'</dt>
%%   <dd>Success without returning any table data (UPDATE, etc.)</dd>
%%   <dt>`{ok, ColumnNames, Rows}'</dt>
%%   <dd>Queries returning one result set of table data</dd>
%%   <dt>`{ok, [{ColumnNames, Rows}, ...]}'</dt>
%%   <dd>Queries returning more than one result set of table data</dd>
%%   <dt>`{error, ServerReason}'</dt>
%%   <dd>MySQL server error</dd>
%%   <dt>`{implicit_commit, NestingLevel, Query}'</dt>
%%   <dd>A DDL statement (e.g. CREATE TABLE, ALTER TABLE, etc.) results in
%%       an implicit commit.
%%
%%       If the caller is in a (nested) transaction, it must be aborted. To be
%%       able to handle this in the caller's process, we also return the
%%       nesting level.</dd>
%%   <dt>`{implicit_rollback, NestingLevel, ServerReason}'</dt>
%%   <dd>This errors results in an implicit rollback: `{1213, <<"40001">>,
%%       <<"Deadlock found when trying to get lock; try restarting "
%%         "transaction">>}'.
%%
%%       If the caller is in a (nested) transaction, it must be aborted. To be
%%       able to handle this in the caller's process, we also return the
%%       nesting level.</dd>
%% </dl>
handle_call(state, _From, #state{socket = undefined} = State) ->
    {reply, State, State};
handle_call(_, _From, #state{socket = undefined} = State) ->
    {reply, {error, reconnecting}, State};
handle_call({query, Query, FilterMap, Timeout}, _From, State) ->
    {Reply, State1} = do_query(Query, FilterMap, Timeout, State),
    {reply, Reply, State1};
handle_call({param_query, Query, Params, FilterMap, default_timeout}, From,
            State) ->
    handle_call({param_query, Query, Params, FilterMap,
                State#state.query_timeout}, From, State);
handle_call({param_query, Query, Params, FilterMap, Timeout}, _From,
            #state{socket = Socket, sockmod = SockMod} = State) ->
    %% Parametrized query: Prepared statement cached with the query as the key
    QueryBin = iolist_to_binary(Query),
    Cache = State#state.query_cache,
    {StmtResult, Cache1} = case mysql_cache:lookup(QueryBin, Cache) of
        {found, FoundStmt, NewCache} ->
            %% Found
            {{ok, FoundStmt}, NewCache};
        not_found ->
            %% Prepare
            setopts(SockMod, Socket, [{active, false}]),
            Rec = mysql_protocol:prepare(Query, SockMod, Socket),
            setopts(SockMod, Socket, [{active, once}]),
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
            execute_stmt(StmtRec, Params, FilterMap, Timeout, State1);
        PrepareError ->
            {reply, PrepareError, State}
    end;
handle_call({execute, Stmt, Args, FilterMap, default_timeout}, From, State) ->
    handle_call({execute, Stmt, Args, FilterMap, State#state.query_timeout},
        From, State);
handle_call({execute, Stmt, Args, FilterMap, Timeout}, _From, State) ->
    case dict:find(Stmt, State#state.stmts) of
        {ok, StmtRec} ->
            execute_stmt(StmtRec, Args, FilterMap, Timeout, State);
        error ->
            {reply, {error, not_prepared}, State}
    end;
handle_call({prepare, Query}, _From, State) ->
    #state{socket = Socket, sockmod = SockMod} = State,
    setopts(SockMod, Socket, [{active, false}]),
    Rec = mysql_protocol:prepare(Query, SockMod, Socket),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Rec, State),
    case Rec of
        #error{} = E ->
            {reply, {error, error_to_reason(E)}, State1};
        #prepared{statement_id = Id} = Stmt ->
            Stmts1 = dict:store(Id, Stmt, State1#state.stmts),
            State2 = State#state{stmts = Stmts1},
            {reply, {ok, Id}, State2}
    end;
handle_call({prepare, Name, Query}, _From, State) when is_atom(Name) ->
    {Reply, State1} = do_named_prepare(Name, Query, State),
    {reply, Reply, State1};
handle_call({unprepare, Stmt}, _From, State) when is_atom(Stmt);
                                                  is_integer(Stmt) ->
    case dict:find(Stmt, State#state.stmts) of
        {ok, StmtRec} ->
            #state{socket = Socket, sockmod = SockMod} = State,
            setopts(SockMod, Socket, [{active, false}]),
            mysql_protocol:unprepare(StmtRec, SockMod, Socket),
            setopts(SockMod, Socket, [{active, once}]),
            State1 = State#state{stmts = dict:erase(Stmt, State#state.stmts)},
            State2 = schedule_ping(State1),
            {reply, ok, State2};
        error ->
            {reply, {error, not_prepared}, State}
    end;
handle_call({change_user, Username, Password, Options}, From,
            State = #state{transaction_levels = []}) ->
    #state{socket = Socket, sockmod = SockMod,
           auth_plugin_data = AuthPluginData,
           server_version = ServerVersion} = State,
    Database = proplists:get_value(database, Options, undefined),
    Queries = proplists:get_value(queries, Options, []),
    Prepares = proplists:get_value(prepare, Options, []),
    setopts(SockMod, Socket, [{active, false}]),
    Result = mysql_protocol:change_user(SockMod, Socket, Username, Password,
                                        AuthPluginData, Database,
                                        ServerVersion),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Result, State),
    State1#state.warning_count > 0 andalso State1#state.log_warnings
        andalso log_warnings(State1, "CHANGE USER"),
    State2 = State1#state{query_cache = empty, stmts = dict:new()},
    case Result of
        #ok{} ->
            State3 = State2#state{user = Username, password = Password},
            case execute_on_connect(Queries, Prepares, State3) of
                {ok, State4} ->
                    {reply, ok, State4};
                {error, Reason} = E ->
                    gen_server:reply(From, E),
                    stop_server(Reason, State3)
            end;
        #error{} = E ->
            gen_server:reply(From, {error, error_to_reason(E)}),
            stop_server(change_user_failed, State2)
    end;
handle_call(reset_connection, _From, #state{socket = Socket, sockmod = SockMod} = State) ->
    setopts(SockMod, Socket, [{active, false}]),
    Result = mysql_protocol:reset_connnection(SockMod, Socket),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Result, State),
    Reply = case Result of
        #ok{} -> ok;
        #error{} = E ->
            %% 'COM_RESET_CONNECTION' is added in MySQL 5.7 and MariaDB 10
            %% "Unkown command" is returned when MySQL =< 5.6 or MariaDB =< 5.5
            {error, error_to_reason(E)}
    end,
    {reply, Reply, State1};

handle_call(warning_count, _From, State) ->
    {reply, State#state.warning_count, State};
handle_call(insert_id, _From, State) ->
    {reply, State#state.insert_id, State};
handle_call(affected_rows, _From, State) ->
    {reply, State#state.affected_rows, State};
handle_call(autocommit, _From, State) ->
    {reply, State#state.status band ?SERVER_STATUS_AUTOCOMMIT /= 0, State};
handle_call(backslash_escapes_enabled, _From, State = #state{status = S}) ->
    {reply, S band ?SERVER_STATUS_NO_BACKSLASH_ESCAPES == 0, State};
handle_call(in_transaction, _From, State) ->
    {reply, State#state.status band ?SERVER_STATUS_IN_TRANS /= 0, State};
handle_call(start_transaction, {FromPid, _},
            State = #state{socket = Socket, sockmod = SockMod,
                           transaction_levels = L, status = Status})
  when Status band ?SERVER_STATUS_IN_TRANS == 0, L == [];
       Status band ?SERVER_STATUS_IN_TRANS /= 0, L /= [] ->
    MRef = erlang:monitor(process, FromPid),
    Query = case L of
        [] -> <<"BEGIN">>;
        _  -> <<"SAVEPOINT s", (integer_to_binary(length(L)))/binary>>
    end,
    setopts(SockMod, Socket, [{active, false}]),
    {ok, [Res = #ok{}]} = mysql_protocol:query(Query, SockMod, Socket,
                                               ?cmd_timeout),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Res, State),
    {reply, ok, State1#state{transaction_levels = [{FromPid, MRef} | L]}};
handle_call(rollback, {FromPid, _},
            State = #state{socket = Socket, sockmod = SockMod, status = Status,
                           transaction_levels = [{FromPid, MRef} | L]})
  when Status band ?SERVER_STATUS_IN_TRANS /= 0 ->
    erlang:demonitor(MRef),
    Query = case L of
        [] -> <<"ROLLBACK">>;
        _  -> <<"ROLLBACK TO s", (integer_to_binary(length(L)))/binary>>
    end,
    setopts(SockMod, Socket, [{active, false}]),
    {ok, [Res = #ok{}]} = mysql_protocol:query(Query, SockMod, Socket,
                                               ?cmd_timeout),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Res, State),
    {reply, ok, State1#state{transaction_levels = L}};
handle_call(commit, {FromPid, _},
            State = #state{socket = Socket, sockmod = SockMod, status = Status,
                           transaction_levels = [{FromPid, MRef} | L]})
  when Status band ?SERVER_STATUS_IN_TRANS /= 0 ->
    erlang:demonitor(MRef),
    Query = case L of
        [] -> <<"COMMIT">>;
        _  -> <<"RELEASE SAVEPOINT s", (integer_to_binary(length(L)))/binary>>
    end,
    setopts(SockMod, Socket, [{active, false}]),
    {ok, [Res = #ok{}]} = mysql_protocol:query(Query, SockMod, Socket,
                                               ?cmd_timeout),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Res, State),
    {reply, ok, State1#state{transaction_levels = L}}.

%% @private
handle_cast({connection_ready, #state{host = Host,
                                      port = Port}= State1}, _State) ->
    error_logger:info_msg("mysql reconnected ~p:~p", [Host, Port]),
    {noreply, schedule_ping(State1)};

handle_cast(reconnect_timeout, State) ->
    stop_server({error, reconnect_timeout}, State);

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @private
handle_info(query_cache, #state{query_cache = Cache,
                                query_cache_time = CacheTime} = State) ->
    %% Evict expired queries/statements in the cache used by query/3.
    {Evicted, Cache1} = mysql_cache:evict_older_than(Cache, CacheTime),
    %% Unprepare the evicted statements
    #state{socket = Socket, sockmod = SockMod} = State,
    setopts(SockMod, Socket, [{active, false}]),
    lists:foreach(fun ({_Query, Stmt}) ->
                      mysql_protocol:unprepare(Stmt, SockMod, Socket)
                  end,
                  Evicted),
    setopts(SockMod, Socket, [{active, once}]),
    %% If nonempty, schedule eviction again.
    mysql_cache:size(Cache1) > 0 andalso
        erlang:send_after(CacheTime, self(), query_cache),
    {noreply, State#state{query_cache = Cache1}};
handle_info({'DOWN', _MRef, _, Pid, _Info}, State) ->
    stop_server({application_process_died, Pid}, State);
handle_info(ping, #state{socket = undefined} = State) ->
    %%tcp_closed and reconnecting
    {noreply, State#state{ping_ref = undefined}};
handle_info(ping, #state{socket = Socket, sockmod = SockMod} = State) ->
    setopts(SockMod, Socket, [{active, false}]),
    Ok = mysql_protocol:ping(SockMod, Socket),
    setopts(SockMod, Socket, [{active, once}]),
    {noreply, update_state(Ok, State)};
handle_info({tcp_closed, _Socket}, State) ->
    is_reference(State#state.ping_ref) andalso erlang:cancel_timer(State#state.ping_ref),
    try_reconnect(tcp_closed, State#state{ping_ref = undefined});
handle_info({tcp_error, _Socket, Reason}, State) ->
    stop_server({tcp_error, Reason}, State);
handle_info(_Info, State) ->
    {noreply, State}.

%% @private
terminate(Reason, #state{socket = Socket, sockmod = SockMod})
  when Socket =/= undefined andalso (Reason == normal orelse Reason == shutdown) ->
      %% Send the goodbye message for politeness.
      setopts(SockMod, Socket, [{active, false}]),
      mysql_protocol:quit(SockMod, Socket);
terminate(_Reason, _State) ->
    ok.

%% @private
code_change(_OldVsn, State = #state{}, _Extra) ->
    {ok, State};
code_change(_OldVsn, _State, _Extra) ->
    {error, incompatible_state}.

%% --- Helpers ---

%% @doc Executes a prepared statement and returns {reply, Reply, NextState}.
execute_stmt(Stmt, Args, FilterMap, Timeout,
             State = #state{socket = Socket, sockmod = SockMod}) ->
    setopts(SockMod, Socket, [{active, false}]),
    {ok, Recs} = case mysql_protocol:execute(Stmt, Args, SockMod, Socket,
                                             FilterMap, Timeout) of
        {error, timeout} when State#state.server_version >= [5, 0, 0] ->
            kill_query(State),
            mysql_protocol:fetch_execute_response(SockMod, Socket,
                                                  FilterMap, ?cmd_timeout);
        {error, timeout} ->
            %% For MySQL 4.x.x there is no way to recover from timeout except
            %% killing the connection itself.
            exit(timeout);
        QueryResult ->
            QueryResult
    end,
    setopts(SockMod, Socket, [{active, once}]),
    State1 = lists:foldl(fun update_state/2, State, Recs),
    State1#state.warning_count > 0 andalso State1#state.log_warnings
        andalso log_warnings(State1, Stmt#prepared.orig_query),
    {Reply, State2} = handle_query_call_result(Recs, Stmt#prepared.orig_query, State1, []),
    {reply, Reply, State2}.

%% @doc Produces a tuple to return as an error reason.
-spec error_to_reason(#error{}) -> mysql:server_reason().
error_to_reason(#error{code = Code, state = State, msg = Msg}) ->
    {Code, State, Msg}.

%% @doc Updates a state with information from a response. Also re-schedules
%% ping.
-spec update_state(#ok{} | #eof{} | any(), #state{}) -> #state{}.
update_state(Rec, State) ->
    State1 = case Rec of
        #ok{status = S, affected_rows = R, insert_id = Id, warning_count = W} ->
            State#state{status = S, affected_rows = R, insert_id = Id,
                        warning_count = W};
        #resultset{status = S, warning_count = W} ->
            State#state{status = S, warning_count = W};
        #prepared{warning_count = W} ->
            State#state{warning_count = W};
        _Other ->
            %% This includes errors.
            %% Reset some things. (Note: We don't reset status and insert_id.)
            State#state{warning_count = 0, affected_rows = 0}
    end,
    schedule_ping(State1).

%% @doc executes an unparameterized query and returns {Reply, NewState}.
do_query(Query, FilterMap, default_timeout,
            #state{query_timeout = DefaultTimeout} = State) ->
    do_query(Query, FilterMap, DefaultTimeout, State);
do_query(Query, FilterMap, Timeout,
            #state{sockmod = SockMod, socket = Socket} = State) ->
    setopts(SockMod, Socket, [{active, false}]),
    Result = mysql_protocol:query(Query, SockMod, Socket, FilterMap, Timeout),
    {ok, Recs} = case Result of
        {error, timeout} when State#state.server_version >= [5, 0, 0] ->
            kill_query(State),
            mysql_protocol:fetch_query_response(SockMod, Socket, FilterMap,
                                                ?cmd_timeout);
        {error, timeout} ->
            %% For MySQL 4.x.x there is no way to recover from timeout except
            %% killing the connection itself.
            exit(timeout);
        QueryResult ->
            QueryResult
    end,
    setopts(SockMod, Socket, [{active, once}]),
    State1 = lists:foldl(fun update_state/2, State, Recs),
    State1#state.warning_count > 0 andalso State1#state.log_warnings
        andalso log_warnings(State1, Query),
    handle_query_call_result(Recs, Query, State1, []).

%% @doc Prepares a named query and returns {{ok, Name}, NewState} or
%% {{error, Reason}, NewState}.
do_named_prepare(Name, Query, State) ->
    #state{socket = Socket, sockmod = SockMod} = State,
    %% First unprepare if there is an old statement with this name.
    setopts(SockMod, Socket, [{active, false}]),
    State1 = case dict:find(Name, State#state.stmts) of
        {ok, OldStmt} ->
            mysql_protocol:unprepare(OldStmt, SockMod, Socket),
            State#state{stmts = dict:erase(Name, State#state.stmts)};
        error ->
            State
    end,
    Rec = mysql_protocol:prepare(Query, SockMod, Socket),
    setopts(SockMod, Socket, [{active, once}]),
    State2 = update_state(Rec, State1),
    case Rec of
        #error{} = E ->
            {{error, error_to_reason(E)}, State2};
        #prepared{} = Stmt ->
            Stmts1 = dict:store(Name, Stmt, State2#state.stmts),
            State3 = State2#state{stmts = Stmts1},
            {{ok, Name}, State3}
    end.

%% @doc Transforms result sets into a structure appropriate to be returned
%% to the client.
handle_query_call_result([], _Query, State, []) ->
    {ok, State};
handle_query_call_result([], _Query, State, [{ColumnNames, Rows}]) ->
    {{ok, ColumnNames, Rows}, State};
handle_query_call_result([], _Query, State, ResultSetsAcc) ->
    {{ok, lists:reverse(ResultSetsAcc)}, State};
handle_query_call_result([Rec|Recs], Query, State = #state{transaction_levels = L}, ResultSetsAcc) ->
    case Rec of
        #ok{status = Status} when Status band ?SERVER_STATUS_IN_TRANS == 0,
                                  L /= [] ->
            %% DDL statements (e.g. CREATE TABLE, ALTER TABLE, etc.) result in
            %% an implicit commit.
            Length = length(L),
            Reply = {implicit_commit, Length, Query},
            [] = demonitor_processes(L, Length),
            {Reply, State#state{transaction_levels = []}};
        #ok{} ->
            handle_query_call_result(Recs, Query, State, ResultSetsAcc);
        #resultset{cols = ColDefs, rows = Rows} ->
            Names = [Def#col.name || Def <- ColDefs],
            ResultSetsAcc1 = [{Names, Rows} | ResultSetsAcc],
            handle_query_call_result(Recs, Query, State, ResultSetsAcc1);
        #error{code = ?ERROR_DEADLOCK} when L /= [] ->
            %% These errors result in an implicit rollback.
            Reply = {implicit_rollback, length(L), error_to_reason(Rec)},
            %% Everything in the transaction is rolled back, except the BEGIN
            %% statement itself. Thus, we are in transaction level 1.
            NewMonitors = demonitor_processes(L, length(L) - 1),
            {Reply, State#state{transaction_levels = NewMonitors}};
        #error{} ->
            {{error, error_to_reason(Rec)}, State}
    end.

%% @doc Schedules (or re-schedules) ping.
schedule_ping(State = #state{ping_timeout = infinity}) ->
    State;
schedule_ping(State = #state{ping_timeout = Timeout, ping_ref = Ref}) ->
    is_reference(Ref) andalso erlang:cancel_timer(Ref),
    State#state{ping_ref = erlang:send_after(Timeout, self(), ping)}.

%% @doc Fetches and logs warnings. Query is the query that gave the warnings.
log_warnings(#state{socket = Socket, sockmod = SockMod}, Query) ->
    setopts(SockMod, Socket, [{active, false}]),
    {ok, [#resultset{rows = Rows}]} = mysql_protocol:query(<<"SHOW WARNINGS">>,
                                                           SockMod, Socket,
                                                           ?cmd_timeout),
    setopts(SockMod, Socket, [{active, once}]),
    Lines = [[Level, " ", integer_to_binary(Code), ": ", Message, "\n"]
             || [Level, Code, Message] <- Rows],
    error_logger:warning_msg("~s in ~s~n", [Lines, Query]).

%% @doc Makes a separate connection and execute KILL QUERY. We do this to get
%% our main connection back to normal. KILL QUERY appeared in MySQL 5.0.0.
kill_query(#state{connection_id = ConnId, host = Host, port = Port,
                  user = User, password = Password, ssl_opts = SSLOpts,
                  cap_found_rows = SetFoundRows}) ->
    %% Connect socket
    SockOpts = [{active, false}, binary, {packet, raw}],
    {ok, Socket0} = gen_tcp:connect(Host, Port, SockOpts),

    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(User, Password, undefined, gen_tcp,
                                      SSLOpts, Socket0, SetFoundRows),
    case Result of
        {ok, #handshake{}, SockMod, Socket} ->
            %% Kill and disconnect
            IdBin = integer_to_binary(ConnId),
            {ok, [#ok{}]} = mysql_protocol:query(<<"KILL QUERY ", IdBin/binary>>,
                                                 SockMod, Socket, ?cmd_timeout),
            mysql_protocol:quit(SockMod, Socket);
        #error{} = E ->
            error_logger:error_msg("Failed to connect to kill query: ~p",
                                   [error_to_reason(E)])
    end.

stop_server(Reason,
            #state{socket = Socket, connection_id = ConnId} = State) ->
  error_logger:error_msg("Connection Id ~p closing with reason: ~p~n",
                         [ConnId, Reason]),
  undefined =/= Socket andalso gen_tcp:close(Socket),
  {stop, Reason, State#state{socket = undefined, connection_id = undefined}}.

setopts(gen_tcp, Socket, Opts) ->
    inet:setopts(Socket, Opts);
setopts(SockMod, Socket, Opts) ->
    SockMod:setopts(Socket, Opts).

demonitor_processes(List, 0) ->
    List;
demonitor_processes([{_FromPid, MRef}|T], Count) ->
    erlang:demonitor(MRef),
    demonitor_processes(T, Count - 1).

%% ---- Reconnect logic ----
reconnect_interval(undefined) ->
    undefined;
reconnect_interval(_) ->
    ?reconnect_interval.

seconds(infinity) ->
    infinity;
seconds(Seconds) when is_integer(Seconds) ->
    timer:seconds(Seconds);
seconds(_) ->
    undefined.

try_reconnect(Reason, #state{reconnect_interval = undefined} = State) ->
    %% If we aren't going to reconnect, then there is nothing else for
    %% this process to do.
    {stop, Reason, State#state{socket = undefined, connection_id = undefined}};
try_reconnect(Reason, #state{connection_id = ConnId, host = Host, port = Port,
                               reconnect_interval = ReconnectInterval,
                               reconnect_timeout = ReconnectTimeout} = State) ->
    error_logger:error_msg("mysql : connection_id <~p> disconnect, "
                           "establishing to ~p:~p due to ~p",
                           [ConnId, Host, Port, Reason]),
    Self = self(),
    Pid = spawn_link(fun() ->
        reconnect_loop(ReconnectTimeout, ReconnectInterval, Self, State) end),

    {noreply, State#state{socket = undefined,
                          connection_id = undefined,
                          reconnect_pid = Pid}}.

%% @doc: Loop until a connection can be established, this includes
%% successfully issuing the auth and select calls. When we have a
%% connection, give the socket to the mysql client.
reconnect_loop(Timeout, Interval, Client, State) when (Timeout > 0) orelse (infinity =:= Timeout) ->
    NewTimeout = update_reconnect_timeout(Timeout, Interval),
    case catch(connecting(State)) of
        {ok, #state{socket = Socket} = State1} ->
            gen_server:cast(Client, {connection_ready, State1}),
            gen_tcp:controlling_process(Socket, Client),
            get_all_messages(),
            ok;
        {error, _Reason} ->
            timer:sleep(Interval),
            reconnect_loop(NewTimeout, Interval, Client, State);
        %% Something bad happened when connecting, like mysql might be
        %% loading the dataset and we got something other than 'OK' in
        %% auth
        _ ->
            timer:sleep(Interval),
            reconnect_loop(NewTimeout, Interval, Client, State)
    end;

reconnect_loop(_Timeout, _Interval, Client, _State) ->
    gen_server:cast(Client, reconnect_timeout).

%% update reconnect timeout
update_reconnect_timeout(infinity, _ReconnectInterval) ->
    infinity;
update_reconnect_timeout(ReconnectTimeout, ReconnectInterval) ->
    ReconnectTimeout - ReconnectInterval.

get_all_messages() ->
    receive _ -> ok
    after   0 -> ok
    end.

connecting(#state{ssl_opts = SSLOpts, cap_found_rows = SetFoundRows,
                  host = Host, port = Port, user = User, password = Password,
                  queries = Queries, prepare = Prepares,
                  database = Database, socket_opts = SockOpts} = State) ->

    {ok, Socket0} = gen_tcp:connect(Host, Port, SockOpts),

    %% If buffer wasn't specifically defined make it at least as
    %% large as recbuf, as suggested by the inet:setopts() docs.
    case proplists:is_defined(buffer, SockOpts) of
        true ->
            ok;
        false ->
            {ok, [{buffer, Buffer}]} = inet:getopts(Socket0, [buffer]),
            {ok, [{recbuf, Recbuf}]} = inet:getopts(Socket0, [recbuf]),
            ok = inet:setopts(Socket0,[{buffer, max(Buffer, Recbuf)}])
    end,
    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(User, Password, Database, gen_tcp, SSLOpts,
                                      Socket0, SetFoundRows),
    case Result of
        {ok, Handshake, SockMod, Socket} ->
            setopts(SockMod, Socket, [{active, once}]),
            #handshake{server_version = Version, connection_id = ConnId,
                       status = Status,
                       auth_plugin_data = AuthPluginData} = Handshake,
            State1 = State#state{server_version = Version, connection_id = ConnId,
                           sockmod = SockMod,
                           socket = Socket,
                           status = Status,
                           auth_plugin_data = AuthPluginData,
                           affected_rows = 0,
                           warning_count = 0,
                           insert_id = 0,
                           reconnect_pid = undefined},
            case execute_on_connect(Queries, Prepares, State1) of
                {ok, State2} ->
                    {ok, State2};
                {error, Reason} ->
                    {stop, Reason}
            end;
        #error{} = E ->
            {stop, error_to_reason(E)}
    end.
