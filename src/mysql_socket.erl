%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
%% Copyright (C) 2016 Feng Lee <feng@emqtt.io>
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

%% @doc MySQL Socket and Receiver.

-module(mysql_socket).

-author("Feng Lee <feng@emqtt.io>").

%% API
-export([connect/4, controlling_process/2, send/2, close/1, fast_close/1, stop/1]).

-export([sockname/1, sockname_s/1, setopts/2, getstat/2]).

%% Internal Export
-export([receiver/2, receiver_loop/3, parser/0]).

-define(MAX_LEN, 16#ffffff).

%% 60 (secs)
-define(TIMEOUT, 60000).

-define(TCP_OPTS, [binary, {packet, raw}, {active, false}, {reuseaddr, true},
                   {nodelay, true}, {reuseaddr, true}, {send_timeout, ?TIMEOUT}]).

%% @doc Connect to MySQL with TCP or SSL transport
-spec(connect(ClientPid, Host, Port, TcpOpts) -> {ok, Socket, Receiver} | {error, any()} when
    ClientPid :: pid(),
    Host      :: inet:ip_address() | string(),
    Port      :: inet:port_number(),
    TcpOpts   :: [gen_tcp:connect_option()],
    Socket    :: inet:socket(),
    Receiver  :: pid()).
connect(ClientPid, Host, Port, TcpOpts) when is_pid(ClientPid) ->
    case gen_tcp:connect(Host, Port, merge_opts(?TCP_OPTS, TcpOpts), ?TIMEOUT) of
        {ok, Socket} -> tune_buffer(Socket),
                        ReceiverPid = spawn_link(?MODULE, receiver, [ClientPid, Socket]),
                        controlling_process(Socket, ReceiverPid),
                        {ok, Socket, ReceiverPid};
        Error        -> Error
    end.

tune_buffer(Socket) ->
    {ok, [{recbuf, RecBuf}, {sndbuf, SndBuf}]} = inet:getopts(Socket, [recbuf, sndbuf]),
    inet:setopts(Socket, [{buffer, max(RecBuf, SndBuf)}]).

merge_opts(Defaults, Options) ->
    lists:foldl(
        fun({Opt, Val}, Acc) ->
                case lists:keymember(Opt, 1, Acc) of
                    true ->
                        lists:keyreplace(Opt, 1, Acc, {Opt, Val});
                    false ->
                        [{Opt, Val}|Acc]
                end;
            (Opt, Acc) ->
                case lists:member(Opt, Acc) of
                    true -> Acc;
                    false -> [Opt | Acc]
                end
        end, Defaults, Options).

%% @doc Socket controlling process
controlling_process(Socket, Pid) when is_port(Socket) ->
    gen_tcp:controlling_process(Socket, Pid).

%% @doc Send Data
-spec(send(Socket, Data) -> ok when
    Socket :: inet:socket(),
    Data   :: binary()).
send(Socket, Data) when is_port(Socket) ->
    gen_tcp:send(Socket, Data).

%% @doc Close Socket.
-spec(close(Socket :: inet:socket()) -> ok).
close(Socket) when is_port(Socket) ->
    gen_tcp:close(Socket).

-spec(fast_close(Socket :: inet:socket()) -> ok).
fast_close(Socket) when is_port(Socket) ->
    catch port_close(Socket), ok.

%% @doc Stop Receiver.
-spec(stop(Receiver :: pid()) -> ok).
stop(Receiver) ->
    Receiver ! stop.

%% @doc Set socket options.
setopts(Socket, Opts) when is_port(Socket) ->
    inet:setopts(Socket, Opts);
setopts(_Socket, _Opts) ->
    ok. %% for unit test

%% @doc Get socket stats.
-spec(getstat(Socket, Stats) -> {ok, Values} | {error, any()} when
    Socket :: inet:socket(),
    Stats  :: list(),
    Values :: list()).
getstat(Socket, Stats) when is_port(Socket) ->
    inet:getstat(Socket, Stats).

%% @doc Socket name.
-spec(sockname(Socket) -> {ok, {Address, Port}} | {error, any()} when
    Socket  :: inet:socket(),
    Address :: inet:ip_address(),
    Port    :: inet:port_number()).
sockname(Socket) when is_port(Socket) ->
    inet:sockname(Socket).

sockname_s(Socket) ->
    case sockname(Socket) of
        {ok, {Addr, Port}} ->
            {ok, lists:flatten(io_lib:format("~s:~p", [maybe_ntoab(Addr), Port]))};
        Error ->
            Error
    end.

%%% Receiver Loop
receiver(ClientPid, Socket) ->
    receiver_activate(ClientPid, Socket, parser()).

receiver_activate(ClientPid, Socket, Parser) ->
    setopts(Socket, [{active, once}]),
    erlang:hibernate(?MODULE, receiver_loop, [ClientPid, Socket, Parser]).

receiver_loop(ClientPid, Socket, Parser) ->
    receive
        {tcp, Socket, Data} ->
            case parse_data(ClientPid, Data, Parser) of
                {ok, NewParser} ->
                    receiver_activate(ClientPid, Socket, NewParser);
                {error, Error} ->
                    exit(Error)
            end;
        {tcp_error, Socket, Reason} ->
            exit({tcp_error, Reason});
        {tcp_closed, Socket} ->
            exit(tcp_closed);
        stop -> 
            close(Socket), exit(normal)
    end.

%%--------------------------------------------------------------------
%% Parse packet
%%--------------------------------------------------------------------

parse_data(_ClientPid, <<>>, Parser) ->
    {ok, Parser};

parse_data(ClientPid, Data, Parser) ->
    case Parser(Data) of
        {more, NewParser} ->
            {ok, NewParser};
        {ok, {SeqNum, Body}, Rest} ->
            ClientPid ! {mysql_recv, self(), {ok, SeqNum, Body}},
            parse_data(ClientPid, Rest, parser());
        {error, Error} ->
            {error, Error}
    end.

%% @doc Parses a packet header (32 bits) and returns a tuple.
%%
%% The client should first read a header and parse it. Then read PacketLength
%% bytes. If there are more packets, read another header and read a new packet
%% length of payload until there are no more packets. The seq num should
%% increment from 0 and may wrap around at 255 back to 0.
%%
%% When all packets are read and the payload of all packets are concatenated, it
%% can be parsed using parse_response/1, etc. depending on what type of response
%% is expected.
%% @private

parser() -> fun(Bin) -> parse_header(Bin, none) end.

parse_header(<<>>, State) ->
    {more, fun(Bin) -> parse_header(Bin, State) end};

parse_header(Bin, State) when size(Bin) < 4 ->
    {more, fun(More) -> parse_header(<<Bin/binary, More/binary>>, State) end};

parse_header(<<?MAX_LEN:24/little, Seq:8, Bin/binary>>, none) ->
    parse_body(Bin, Seq, ?MAX_LEN, {more, <<>>});

parse_header(<<?MAX_LEN:24/little, Seq:8, Bin/binary>>, {more, Acc}) ->
    parse_body(Bin, Seq, ?MAX_LEN, {more, Acc});

parse_header(<<Len:24/little, Seq:8, Bin/binary>>, none) ->
    parse_body(Bin, Seq, Len, {done, <<>>});

parse_header(<<Len:24/little, Seq:8, Bin/binary>>, {more, Acc}) ->
    parse_body(Bin, Seq, Len, {done, Acc}).

parse_body(Bin, Seq, Len, State) when size(Bin) < Len ->
    {more, fun(More) -> parse_body(<<Bin/binary, More/binary>>, Seq, Len, State) end};

parse_body(Bin, _Seq, Len, {more, Acc}) ->
    <<Body:Len/binary, Rest/binary>> = Bin,
    parse_header(Rest, {more, <<Acc/binary, Body/binary>>});

parse_body(Bin, Seq, Len, {done, Acc}) ->
    <<Body:Len/binary, Rest/binary>> = Bin,
    {ok, {Seq, <<Acc/binary, Body/binary>>}, Rest}.

%%--------------------------------------------------------------------
%% utilities
%%--------------------------------------------------------------------

maybe_ntoab(Addr) when is_tuple(Addr) -> ntoab(Addr);
maybe_ntoab(Host)                     -> Host.

ntoa({0,0,0,0,0,16#ffff,AB,CD}) ->
    inet_parse:ntoa({AB bsr 8, AB rem 256, CD bsr 8, CD rem 256});
ntoa(IP) ->
    inet_parse:ntoa(IP).

ntoab(IP) ->
    Str = ntoa(IP),
    case string:str(Str, ":") of
        0 -> Str;
        _ -> "[" ++ Str ++ "]"
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parser_test() ->
    %% Example from "MySQL Internals", revision 307, section 14.1.3.3 EOF_Packet
    Packet = <<16#05, 16#00, 16#00, 16#05, 16#fe, 16#00, 16#00, 16#02, 16#00>>,
    %% Check header contents and body length
    ?assertEqual({ok, {5, <<16#fe, 16#00, 16#00, 16#02, 16#00>>}, <<>>}, (parser())(Packet)),
    ok.

-endif.

