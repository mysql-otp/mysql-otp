-module(mysql_connection).
-behaviour(gen_server).

-export([start_link/1]).

%% Gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-include("records.hrl").

start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%% --- Gen_server ballbacks ---

-define(default_host, "localhost").
-define(default_port, 3306).
-define(default_user, <<>>).
-define(default_password, <<>>).
-define(default_timeout, infinity).

-record(state, {socket, affected_rows = 0, status = 0, warning_count = 0,
                insert_id = 0}).

init(Opts) ->
    %% Connect
    Host     = proplists:get_value(host,     Opts, ?default_host),
    Port     = proplists:get_value(port,     Opts, ?default_port),
    User     = proplists:get_value(user,     Opts, ?default_user),
    Password = proplists:get_value(password, Opts, ?default_password),
    Timeout  = proplists:get_value(timeout,  Opts, ?default_timeout),

    %% Connect socket
    SockOpts = [{active, false}, binary, {packet, raw}],
    {ok, Socket} = gen_tcp:connect(Host, Port, SockOpts),

    %% Receive handshake
    {ok, HandshakeBin, 1} = recv(Socket, 0, Timeout),
    Handshake = mysql_protocol:parse_handshake(HandshakeBin),

    %% Reply to handshake
    HandshakeResp =
        mysql_protocol:build_handshake_response(Handshake, User, Password),
    {ok, 2} = send(Socket, HandshakeResp, 1),

    %% Receive connection ok or error
    {ok, ContBin, 3} = recv(Socket, 2, Timeout),
    case mysql_protocol:parse_handshake_confirm(ContBin) of
        #ok_packet{status = Status} ->
            {ok, #state{status = Status, socket = Socket}};
        #error_packet{msg = Reason} ->
            {stop, Reason}
    end.

handle_call({'query', Query}, _From, State) when is_binary(Query) ->
    Req = mysql_protocol:build_query(Query),
    Resp = call_db(State, Req),
    Rec = mysql_protocol:parse_query_response(Resp),
    State1 = update_state(State, Rec),
    case Rec of
        #ok_packet{} ->
            {reply, ok, State1};
        #error_packet{msg = Msg} ->
            {reply, {error, Msg}, State1}
        %% TODO: Add result set here.
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

%% @doc Updates a state with information from a response.
-spec update_state(#state{}, #ok_packet{} | #error_packet{} | #eof_packet{}) ->
    #state{}.
update_state(State, #ok_packet{status = S, affected_rows = R,
                               insert_id = Id, warning_count = W}) ->
    State#state{status = S, affected_rows = R, insert_id = Id,
                warning_count = W};
update_state(State, #error_packet{}) ->
    State;
update_state(State, #eof_packet{status = S, warning_count = W}) ->
    State#state{status = S, warning_count = W}.

%% @doc Sends data to mysql and receives the response.
call_db(State, PacketBody) ->
    call_db(State, PacketBody, infinity).

%% @doc Sends data to mysql and receives the response.
call_db(#state{socket = Socket}, PacketBody, Timeout) ->
    {ok, SeqNum} = send(Socket, PacketBody, 0),
    {ok, Response, _SeqNum} = recv(Socket, SeqNum, Timeout),
    Response.

%% @doc Sends data and returns {ok, SeqNum1} where SeqNum1 is the next sequence
%% number.
-spec send(Socket :: gen_tcp:socket(), Data :: binary(), SeqNum :: integer()) ->
    {ok, NextSeqNum :: integer()}.
send(Socket, Data, SeqNum) ->
    {WithHeaders, SeqNum1} = mysql_protocol:add_packet_headers(Data, SeqNum),
    ok = gen_tcp:send(Socket, WithHeaders),
    {ok, SeqNum1}.

%% @doc Receives data from the server and removes packet headers. Returns the
%% next packet sequence number.
-spec recv(Socket :: gen_tcp:socket(), SeqNum :: integer(),
           Timeout :: timeout()) ->
    {ok, Data :: binary(), NextSeqNum :: integer()}.
recv(Socket, SeqNum, Timeout) ->
    recv(Socket, SeqNum, Timeout, <<>>).

%% @doc Receives data from the server and removes packet headers. Returns the
%% next packet sequence number.
-spec recv(Socket :: gen_tcp:socket(), ExpectSeqNum :: integer(),
           Timeout :: timeout(), Acc :: binary()) ->
    {ok, Data :: binary(), NextSeqNum :: integer()}.
recv(Socket, ExpectSeqNum, Timeout, Acc) ->
    {ok, Header} = gen_tcp:recv(Socket, 4, Timeout),
    {Size, ExpectSeqNum, More} = mysql_protocol:parse_packet_header(Header),
    {ok, Body} = gen_tcp:recv(Socket, Size, Timeout),
    Acc1 = <<Acc/binary, Body/binary>>,
    NextSeqNum = (ExpectSeqNum + 1) band 16#ff,
    case More of
        false -> {ok, Acc1, NextSeqNum};
        true  -> recv(Socket, NextSeqNum, Acc1)
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

connect_test() ->
    {ok, Pid} = start_link([{user, "test"}, {password, "test"}]),
    %ok = gen_server:call(Pid, {'query', <<"CREATE DATABASE foo">>}),
    ok = gen_server:call(Pid, {'query', <<"USE foo">>}),
    ok = gen_server:call(Pid, {'query', <<"DROP TABLE IF EXISTS foo">>}),
    1 = gen_server:call(Pid, warning_count),
    {error, <<"You h", _/binary>>} = gen_server:call(Pid, {'query', <<"FOO">>}),
    ok.

-endif.
