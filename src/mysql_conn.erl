%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014-2021 Viktor Söderqvist
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
-define(default_connect_timeout, 5000).
-define(default_query_timeout, infinity).
-define(default_query_cache_time, 60000). %% for query/3.
-define(default_ping_timeout, 60000).

-define(cmd_timeout, 3000). %% Timeout used for various commands to the server

%% Errors that cause "implicit rollback"
-define(ERROR_DEADLOCK, 1213).

%% --- Gen_server callbacks ---

-include("records.hrl").
-include("server_status.hrl").

%% Gen_server state
-record(state, {server_version, connection_id, socket, sockmod, tcp_opts, ssl_opts,
                host, port, user, password, database, queries, prepares,
                auth_plugin_name, auth_plugin_data, allowed_local_paths,
                log_warnings, log_slow_queries,
                connect_timeout, ping_timeout, query_timeout, query_cache_time,
                affected_rows = 0, status = 0, warning_count = 0, insert_id = 0,
                transaction_levels = [], ping_ref = undefined,
                stmts = dict:new(), query_cache = empty, cap_found_rows = false,
                float_as_decimal = false}).

%% @private
init(Opts) ->
    %% Connect
    Host           = proplists:get_value(host, Opts, ?default_host),

    DefaultPort = case Host of
        {local, _LocalAddr} -> 0;
        _NonLocalAddr -> ?default_port
    end,
    Port              = proplists:get_value(port, Opts, DefaultPort),

    User              = proplists:get_value(user, Opts, ?default_user),
    Password          = proplists:get_value(password, Opts, ?default_password),
    Database          = proplists:get_value(database, Opts, undefined),
    AllowedLocalPaths = proplists:get_value(allowed_local_paths, Opts, []),
    LogWarn           = proplists:get_value(log_warnings, Opts, true),
    LogSlow           = proplists:get_value(log_slow_queries, Opts, false),
    KeepAlive         = proplists:get_value(keep_alive, Opts, false),
    ConnectTimeout    = proplists:get_value(connect_timeout, Opts,
                                            ?default_connect_timeout),
    QueryTimeout      = proplists:get_value(query_timeout, Opts,
                                            ?default_query_timeout),
    QueryCacheTime    = proplists:get_value(query_cache_time, Opts,
                                            ?default_query_cache_time),
    TcpOpts           = proplists:get_value(tcp_options, Opts, []),
    SetFoundRows      = proplists:get_value(found_rows, Opts, false),
    SSLOpts           = proplists:get_value(ssl, Opts, undefined),

    Queries           = proplists:get_value(queries, Opts, []),
    Prepares          = proplists:get_value(prepare, Opts, []),
    FloatAsDecimal    = proplists:get_value(float_as_decimal, Opts, false),

    true = lists:all(fun mysql_protocol:valid_path/1, AllowedLocalPaths),

    PingTimeout = case KeepAlive of
        true         -> ?default_ping_timeout;
        false        -> infinity;
        N when N > 0 -> N
    end,

    State0 = #state{
        tcp_opts = TcpOpts,
        ssl_opts = SSLOpts,
        host = Host, port = Port,
        user = User, password = Password,
        database = Database,
        allowed_local_paths = AllowedLocalPaths,
        queries = Queries, prepares = Prepares,
        log_warnings = LogWarn, log_slow_queries = LogSlow,
        connect_timeout = ConnectTimeout,
        ping_timeout = PingTimeout,
        query_timeout = QueryTimeout,
        query_cache_time = QueryCacheTime,
        cap_found_rows = (SetFoundRows =:= true),
        float_as_decimal = FloatAsDecimal
    },

    case proplists:get_value(connect_mode, Opts, synchronous) of
        synchronous ->
            case connect(State0) of
                {ok, State1} ->
                    {ok, State1};
                {error, Reason} ->
                    {stop, Reason}
            end;
        asynchronous ->
            gen_server:cast(self(), connect),
            {ok, State0};
        lazy ->
            {ok, State0}
    end.

connect(#state{connect_timeout = ConnectTimeout} = State) ->
    MainPid = self(),
    Pid = spawn_link(
        fun () ->
            {ok, State1}=connect_socket(State),
            case handshake(State1) of
                {ok, #state{sockmod = SockMod, socket = Socket} = State2} ->
                    SockMod:controlling_process(Socket, MainPid),
                    MainPid ! {self(), {ok, State2}};
                {error, _} = E ->
                    MainPid ! {self(), E}
            end
        end
    ),
    receive
        {Pid, {ok, State3}} ->
            post_connect(State3);
        {Pid, {error, _} = E} ->
            E
    after ConnectTimeout ->
        unlink(Pid),
        exit(Pid, kill),
        {error, timeout}
    end.

connect_socket(#state{tcp_opts = TcpOpts, host = Host, port = Port} = State) ->
    %% Connect socket
    SockOpts = sanitize_tcp_opts(TcpOpts),
    {ok, Socket} = gen_tcp:connect(Host, Port, SockOpts),

    %% If buffer wasn't specifically defined make it at least as
    %% large as recbuf, as suggested by the inet:setopts() docs.
    case proplists:is_defined(buffer, TcpOpts) of
        true ->
            ok;
        false ->
            {ok, [{buffer, Buffer}]} = inet:getopts(Socket, [buffer]),
            {ok, [{recbuf, Recbuf}]} = inet:getopts(Socket, [recbuf]),
            ok = inet:setopts(Socket, [{buffer, max(Buffer, Recbuf)}])
    end,

    {ok, State#state{socket = Socket}}.

sanitize_tcp_opts([{inet_backend, _} = InetBackend | TcpOpts0]) ->
    %% This option is be used to turn on the experimental socket backend for
    %% gen_tcp/inet (OTP/23). If given, it must remain the first option in the
    %% list.
    [InetBackend | sanitize_tcp_opts(TcpOpts0)];
sanitize_tcp_opts(TcpOpts0) ->
    TcpOpts1 = lists:filter(
        fun
            ({mode, _}) -> false;
            (binary) -> false;
            (list) -> false;
            ({packet, _}) -> false;
            ({active, _}) -> false;
            (_) -> true
        end,
        TcpOpts0
    ),
    TcpOpts2 = case lists:keymember(nodelay, 1, TcpOpts1) of
        true -> TcpOpts1;
        false -> [{nodelay, true} | TcpOpts1]
    end,
    [binary, {packet, raw}, {active, false} | TcpOpts2].

handshake(#state{socket = Socket0, ssl_opts = SSLOpts,
          host = Host, user = User, password = Password, database = Database,
          cap_found_rows = SetFoundRows} = State0) ->
    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(Host, User, Password, Database, gen_tcp,
                                      SSLOpts, Socket0, SetFoundRows),
    case Result of
        {ok, Handshake, SockMod, Socket} ->
            setopts(SockMod, Socket, [{active, once}]),
            #handshake{server_version = Version, connection_id = ConnId,
                       status = Status,
                       auth_plugin_name = AuthPluginName,
                       auth_plugin_data = AuthPluginData} = Handshake,
            State1 = State0#state{server_version = Version, connection_id = ConnId,
                           sockmod = SockMod,
                           socket = Socket,
                           auth_plugin_name = AuthPluginName,
                           auth_plugin_data = AuthPluginData,
                           status = Status},
            {ok, State1};
        #error{} = E ->
            {error, error_to_reason(E)}
    end.

post_connect(#state{queries = Queries, prepares = Prepares} = State) ->
    case execute_on_connect(Queries, Prepares, State) of
        {ok, State1} ->
            process_flag(trap_exit, true),
            State2 = schedule_ping(State1),
            {ok, State2};
        {error, _} = E ->
            E
    end.

execute_on_connect([], [], State) ->
    {ok, State};
execute_on_connect([], [{Name, Stmt}|Prepares], State) ->
    case named_prepare(Name, Stmt, State) of
        {{ok, Name}, State1} ->
            execute_on_connect([], Prepares, State1);
        {{error, _} = E, _} ->
            E
    end;
execute_on_connect([Query|Queries], Prepares, State) ->
    case query(Query, no_filtermap_fun, default_timeout, State) of
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
handle_call(is_connected, _, #state{socket = Socket} = State) ->
    {reply, Socket =/= undefined, State};
handle_call(Msg, From, #state{socket = undefined} = State) ->
    case connect(State) of
        {ok, State1} ->
            handle_call(Msg, From, State1);
        {error, _} = E ->
            {stop, E, State}
    end;
handle_call({query, Query, FilterMap, Timeout}, _From, State) ->
    {Reply, State1} = query(Query, FilterMap, Timeout, State),
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
            {Reply, State2} = execute_stmt(StmtRec, Params, FilterMap, Timeout, State1),
            {reply, Reply, State2};
        PrepareError ->
            {reply, PrepareError, State}
    end;
handle_call({execute, Stmt, Args, FilterMap, default_timeout}, From, State) ->
    handle_call({execute, Stmt, Args, FilterMap, State#state.query_timeout},
        From, State);
handle_call({execute, Stmt, Args, FilterMap, Timeout}, _From, State) ->
    case dict:find(Stmt, State#state.stmts) of
        {ok, StmtRec} ->
            {Reply, State1} = execute_stmt(StmtRec, Args, FilterMap, Timeout, State),
            {reply, Reply, State1};
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
    {Reply, State1} = named_prepare(Name, Query, State),
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
           auth_plugin_name = AuthPluginName,
           auth_plugin_data = AuthPluginData,
           server_version = ServerVersion} = State,
    Database = proplists:get_value(database, Options, undefined),
    Queries = proplists:get_value(queries, Options, []),
    Prepares = proplists:get_value(prepare, Options, []),
    setopts(SockMod, Socket, [{active, false}]),
    Result = mysql_protocol:change_user(SockMod, Socket, Username, Password,
                                        AuthPluginName, AuthPluginData, Database,
                                        ServerVersion),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Result, State),
    State1#state.warning_count > 0 andalso State1#state.log_warnings
        andalso log_warnings(State1, "CHANGE USER"),
    State2 = State1#state{query_cache = empty, stmts = dict:new()},
    case Result of
        #ok{} ->
            State3 = State2#state{user = Username, password = Password,
                                  database=Database, queries=Queries,
                                  prepares=Prepares},
            case post_connect(State3) of
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
                                               [], no_filtermap_fun,
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
                                               [], no_filtermap_fun,
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
                                               [], no_filtermap_fun,
                                               ?cmd_timeout),
    setopts(SockMod, Socket, [{active, once}]),
    State1 = update_state(Res, State),
    {reply, ok, State1#state{transaction_levels = L}}.

%% @private
handle_cast(connect, #state{socket = undefined} = State) ->
    case connect(State) of
        {ok, State1} ->
            {noreply, State1};
        {error, _} = E ->
            {stop, E, State}
    end;
handle_cast(connect, State) ->
    {noreply, State};
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
handle_info(ping, #state{socket = Socket, sockmod = SockMod} = State) ->
    setopts(SockMod, Socket, [{active, false}]),
    #ok{} = mysql_protocol:ping(SockMod, Socket),
    setopts(SockMod, Socket, [{active, once}]),
    {noreply, schedule_ping(State)};
handle_info({tcp_closed, _Socket}, State) ->
    {stop, normal, State#state{socket = undefined, connection_id = undefined}}; 
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

%% @doc Executes a prepared statement and returns {Reply, NewState}.
execute_stmt(Stmt, Args, FilterMap, Timeout, State) ->
    #state{socket = Socket, sockmod = SockMod,
           allowed_local_paths = AllowedPaths,
           float_as_decimal = FloatAsDecimal} = State,
    Args1 = case FloatAsDecimal of
                false ->
                    Args;
                _ ->
                    [float_to_decimal(Arg, FloatAsDecimal) || Arg <- Args]
            end,
    setopts(SockMod, Socket, [{active, false}]),
    {ok, Recs} = case mysql_protocol:execute(Stmt, Args1, SockMod, Socket,
                                             AllowedPaths, FilterMap,
                                             Timeout) of
        {error, timeout} when State#state.server_version >= [5, 0, 0] ->
            kill_query(State),
            mysql_protocol:fetch_execute_response(SockMod, Socket,
                                                  [], FilterMap, ?cmd_timeout);
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
    handle_query_call_result(Recs, Stmt#prepared.orig_query, State1).

%% @doc Formats floats as decimals, optionally with a given number of decimals.
float_to_decimal(Arg, true) when is_float(Arg) ->
    {decimal, list_to_binary(io_lib:format("~w", [Arg]))};
float_to_decimal(Arg, N) when is_float(Arg), is_integer(N) ->
    {decimal, float_to_binary(Arg, [{decimals, N}, compact])};
float_to_decimal(Arg, _) ->
    Arg.

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
query(Query, FilterMap, default_timeout,
      #state{query_timeout = DefaultTimeout} = State) ->
    query(Query, FilterMap, DefaultTimeout, State);
query(Query, FilterMap, Timeout, State) ->
    #state{sockmod = SockMod, socket = Socket,
           allowed_local_paths = AllowedPaths} = State,
    setopts(SockMod, Socket, [{active, false}]),
    Result = mysql_protocol:query(Query, SockMod, Socket, AllowedPaths,
                                  FilterMap, Timeout),
    {ok, Recs} = case Result of
        {error, timeout} when State#state.server_version >= [5, 0, 0] ->
            kill_query(State),
            mysql_protocol:fetch_query_response(SockMod, Socket,
                                                [], FilterMap,
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
    handle_query_call_result(Recs, Query, State1).

%% @doc Prepares a named query and returns {{ok, Name}, NewState} or
%% {{error, Reason}, NewState}.
named_prepare(Name, Query, State) ->
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
handle_query_call_result([_] = Recs, Query, State) ->
    handle_query_call_result(Recs, not_applicable, Query, State, []);
handle_query_call_result(Recs, Query, State) ->
    handle_query_call_result(Recs, 1, Query, State, []).

handle_query_call_result([], _RecNum, _Query, State, []) ->
    {ok, State};
handle_query_call_result([], _RecNum, _Query, State, [{ColumnNames, Rows}]) ->
    {{ok, ColumnNames, Rows}, State};
handle_query_call_result([], _RecNum, _Query, State, ResultSetsAcc) ->
    {{ok, lists:reverse(ResultSetsAcc)}, State};
handle_query_call_result([Rec|Recs], RecNum, Query,
                         #state{transaction_levels = L} = State,
                         ResultSetsAcc) ->
    RecNum1 = case RecNum of
        not_applicable -> not_applicable;
        _ -> RecNum + 1
    end,
    case Rec of
        #ok{status = Status} when Status band ?SERVER_STATUS_IN_TRANS == 0,
                                  L /= [] ->
            %% DDL statements (e.g. CREATE TABLE, ALTER TABLE, etc.) result in
            %% an implicit commit.
            Length = length(L),
            Reply = {implicit_commit, Length, Query},
            [] = demonitor_processes(L, Length),
            {Reply, State#state{transaction_levels = []}};
        #ok{status = Status} ->
            maybe_log_slow_query(State, Status, RecNum, Query),
            handle_query_call_result(Recs, RecNum1, Query, State, ResultSetsAcc);
        #resultset{cols = ColDefs, rows = Rows, status = Status} ->
            Names = [Def#col.name || Def <- ColDefs],
            ResultSetsAcc1 = [{Names, Rows} | ResultSetsAcc],
            maybe_log_slow_query(State, Status, RecNum, Query),
            handle_query_call_result(Recs, RecNum1, Query, State, ResultSetsAcc1);
        #error{code = ?ERROR_DEADLOCK} when L /= [] ->
            %% These errors result in an implicit rollback.
            Reply = {implicit_rollback, length(L), error_to_reason(Rec)},
            %% The transaction is rollbacked, except the BEGIN, so we're still
            %% in a transaction.  (In 5.7+, also the BEGIN has been rolled back,
            %% but here we assume the old behaviour.)
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
                                                           [], no_filtermap_fun,
                                                           ?cmd_timeout),
    setopts(SockMod, Socket, [{active, once}]),
    Lines = [[Level, " ", integer_to_binary(Code), ": ", Message, "\n"]
             || [Level, Code, Message] <- Rows],
    error_logger:warning_msg("~s in ~s~n", [Lines, Query]).

%% @doc Logs slow queries. Query is the query that gave the warnings.
maybe_log_slow_query(#state{log_slow_queries = true}, S, RecNum, Query)
  when S band ?SERVER_QUERY_WAS_SLOW /= 0 ->
    IndexHint = if
        S band ?SERVER_STATUS_NO_GOOD_INDEX_USED /= 0 ->
            " (with no good index)";
        S band ?SERVER_STATUS_NO_INDEX_USED /= 0 ->
            " (with no index)";
        true ->
            ""
    end,
    QueryNumHint = case RecNum of
        not_applicable ->
            "";
        _ ->
            io_lib:format(" #~b", [RecNum])
    end,
    error_logger:warning_msg("MySQL query~s~s was slow: ~s~n",
                             [QueryNumHint, IndexHint, Query]);
maybe_log_slow_query(_, _, _, _) ->
    ok.

%% @doc Makes a separate connection and execute KILL QUERY. We do this to get
%% our main connection back to normal. KILL QUERY appeared in MySQL 5.0.0.
kill_query(#state{connection_id = ConnId, host = Host, port = Port,
                  user = User, password = Password, ssl_opts = SSLOpts,
                  cap_found_rows = SetFoundRows}) ->
    %% Connect socket
    SockOpts = [{active, false}, binary, {packet, raw}],
    {ok, Socket0} = gen_tcp:connect(Host, Port, SockOpts),

    %% Exchange handshake communication.
    Result = mysql_protocol:handshake(Host, User, Password, undefined, gen_tcp,
                                      SSLOpts, Socket0, SetFoundRows),
    case Result of
        {ok, #handshake{}, SockMod, Socket} ->
            %% Kill and disconnect
            IdBin = integer_to_binary(ConnId),
            {ok, [#ok{}]} = mysql_protocol:query(<<"KILL QUERY ", IdBin/binary>>,
                                                 SockMod, Socket,
                                                 [], no_filtermap_fun,
                                                 ?cmd_timeout),
            mysql_protocol:quit(SockMod, Socket);
        #error{} = E ->
            error_logger:error_msg("Failed to connect to kill query: ~p",
                                   [error_to_reason(E)])
    end.

stop_server(Reason, #state{socket = undefined} = State) ->
  {stop, Reason, State};
stop_server(Reason,
            #state{socket = Socket, connection_id = ConnId} = State) ->
  error_logger:error_msg("Connection Id ~p closing with reason: ~p~n",
                         [ConnId, Reason]),
  ok = gen_tcp:close(Socket),
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
