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

%% A mysql connection implemented as a gen_server. This is a gen_server callback
%% module only. The API functions are located in the mysql module.
-module(mysql_connection).
-behaviour(gen_server).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

%% Some defaults
-define(default_host, "localhost").
-define(default_port, 3306).
-define(default_user, <<>>).
-define(default_password, <<>>).
-define(default_timeout, infinity).

-include("records.hrl").

%% Gen_server state
-record(state, {socket, timeout = infinity, affected_rows = 0, status = 0,
                warning_count = 0, insert_id = 0, stmts = dict:new()}).

%% A tuple representing a MySQL server error, typically returned in the form
%% {error, reason()}.
-type reason() :: {Code :: integer(), SQLState :: binary(), Msg :: binary()}.

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
            {ok, State1};
        #error{} = E ->
            {stop, error_to_reason(E)}
    end.

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
        #resultset{column_definitions = ColDefs, rows = Rows} ->
            Names = [Def#column_definition.name || Def <- ColDefs],
            {reply, {ok, Names, Rows}, State1}
    end;
handle_call({execute, Stmt, Args}, _From, State) when is_integer(Stmt);
                                                      is_atom(Stmt) ->
    %% TODO: Return {error, not_prepared} instead of crashing if not found.
    StmtRec = dict:fetch(Stmt, State#state.stmts),
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
        #resultset{column_definitions = ColDefs, rows = Rows} ->
            Names = [Def#column_definition.name || Def <- ColDefs],
            {reply, {ok, Names, Rows}, State1}
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
handle_call(warning_count, _From, State) ->
    {reply, State#state.warning_count, State};
handle_call(insert_id, _From, State) ->
    {reply, State#state.insert_id, State};
handle_call(affected_rows, _From, State) ->
    {reply, State#state.affected_rows, State};
handle_call(get_state, _From, State) ->
    %% *** FOR DEBUGGING ***
    %% TODO: Delete this.
    {reply, State, State}.

handle_cast(_, _) -> todo.

handle_info(_, _) -> todo.

terminate(_, _) -> todo.

code_change(_, _, _) -> todo.

%% --- Helpers ---

%% @doc Produces a tuple to return when an error needs to be returned to in the
%% public API.
-spec error_to_reason(#error{}) -> reason().
error_to_reason(#error{code = Code, state = State, msg = Msg}) ->
    {Code, State, Msg}.

%% @doc Updates a state with information from a response.
-spec update_state(#state{}, #ok{} | #eof{} | any()) -> #state{}.
update_state(State, #ok{status = S, affected_rows = R,
                        insert_id = Id, warning_count = W}) ->
    State#state{status = S, affected_rows = R, insert_id = Id,
                warning_count = W};
update_state(State, #eof{status = S, warning_count = W}) ->
    State#state{status = S, warning_count = W, insert_id = 0,
                affected_rows = 0};
update_state(State, _Other) ->
    %% This includes errors, resultsets, etc.
    %% Reset warnings, etc. (Note: We don't reset 'status'.)
    State#state{warning_count = 0, insert_id = 0, affected_rows = 0}.
