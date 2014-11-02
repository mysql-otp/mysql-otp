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
-record(state, {socket, affected_rows = 0, status = 0, warning_count = 0,
                insert_id = 0}).

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
    Result = mysql_protocol:handshake(User, Password, Database,
                                      fun (Data) ->
                                          gen_tcp:send(Socket, Data)
                                      end,
                                      fun (Size) ->
                                          gen_tcp:recv(Socket, Size, Timeout)
                                      end),
    case Result of
        #ok{status = Status} ->
            {ok, #state{status = Status, socket = Socket}};
        #error{} = E ->
            {stop, error_to_reason(E)}
    end.

handle_call({query, Query}, _From, State) when is_binary(Query) ->
    Rec = mysql_protocol:query_tcp(Query, State#state.socket,
                                   infinity),
    State1 = update_state(State, Rec),
    case Rec of
        #ok{} ->
            {reply, ok, State1};
        #error{} = E ->
            {reply, {error, error_to_reason(E)}, State1};
        #text_resultset{column_definitions = ColDefs, rows = Rows} ->
            Names = [Def#column_definition.name || Def <- ColDefs],
            Rows1 = decode_text_rows(ColDefs, Rows),
            {reply, {ok, Names, Rows1}, State1}
    end;
handle_call(warning_count, _From, State) ->
    {reply, State#state.warning_count, State};
handle_call(insert_id, _From, State) ->
    {reply, State#state.insert_id, State};
handle_call(status_flags, _From, State) ->
    %% Bitmask of status flags from the last ok packet, etc.
    {reply, State#state.status, State}.

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

%% @doc Uses a list of column definitions to decode rows returned in the text
%% protocol. Returns the rows with values as for their type their appropriate
%% Erlang terms.
decode_text_rows(ColDefs, Rows) ->
    [decode_text_row_acc(ColDefs, Row, []) || Row <- Rows].

decode_text_row_acc([#column_definition{type = T} | Defs], [V | Vs], Acc) ->
    Term = mysql_text_protocol:text_to_term(T, V),
    decode_text_row_acc(Defs, Vs, [Term | Acc]);
decode_text_row_acc([], [], Acc) ->
    lists:reverse(Acc).
