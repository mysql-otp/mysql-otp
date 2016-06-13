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

%% @doc This module implements parts of the MySQL client/server protocol.
%%
%% The protocol is described in the document "MySQL Internals" which can be
%% found under "MySQL Documentation: Expert Guides" on http://dev.mysql.com/.
%%
%% TCP communication is not handled in this module. Most of the public functions
%% take funs for data communitaction as parameters.
%% @private

-module(mysql_protocol).

-export([init/2]).

-export([handshake/5, quit/2, ping/2, query/4, fetch_query_response/3,
         prepare/3, unprepare/3, execute/5, fetch_execute_response/3]).


-define(DEFAULT_TIMEOUT, 60000).

-include("records.hrl").
-include("protocol.hrl").
-include("server_status.hrl").

%% Macros for pattern matching on packets.
-define(ok_pattern, <<?OK, _/binary>>).
-define(error_pattern, <<?ERROR, _/binary>>).
-define(eof_pattern, <<?EOF, _:4/binary>>).

-type(parameter() :: any()).

-type(protocol() :: {?MODULE, list(parameter())}).

%% @doc Init protocol object
init(Socket, Receiver) ->
    {?MODULE, [Socket, Receiver]}.

%% @doc Performs a handshake using the supplied functions for communication.
%% Returns an ok or an error record. Raises errors when various unimplemented
%% features are requested.
-spec(handshake(iodata(), iodata(), iodata() | undefined, timeout(), protocol()) ->
    #handshake{} | #error{}).
handshake(Username, Password, Database, Timeout, {?MODULE, [Socket, Receiver]}) ->
    SeqNum0 = 0,
    {ok, HandshakePacket, SeqNum1} = recv_packet(Receiver, SeqNum0, Timeout),
    Handshake = mysql_parser:parse_handshake(HandshakePacket),
    Response = build_handshake_response(Handshake, Username, Password, Database),
    {ok, SeqNum2} = send_packet(Socket, Response, SeqNum1),
    {ok, ConfirmPacket, _SeqNum3} = recv_packet(Receiver, SeqNum2, Timeout),
    case mysql_parser:parse_handshake_confirm(ConfirmPacket) of
        #ok{status = OkStatus} ->
            OkStatus = Handshake#handshake.status,
            Handshake;
        Error ->
            Error
    end.

-spec(quit(protocol()) -> ok).
quit({?MODULE, [Socket, Receiver]}) ->
    {ok, SeqNum1} = send_packet(Socket, <<?COM_QUIT>>, 0),
    case recv_packet(Receiver, SeqNum1, ?DEFAULT_TIMEOUT) of
        {error, closed} -> ok;            %% MySQL 5.5.40 and more
        {ok, ?ok_pattern, _SeqNum2} -> ok %% Some older MySQL versions?
    end.

-spec(ping(protocol()) -> #ok{}).
ping({?MODULE, [Socket, Receiver]}) ->
    {ok, SeqNum1} = send_packet(Socket, <<?COM_PING>>, 0),
    {ok, OkPacket, _SeqNum2} = recv_packet(Receiver, SeqNum1),
    mysql_parser:parse_ok_packet(OkPacket).

-spec(query(Query :: iodata(), timeout(), protocol()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}).
query(Query, Timeout, {?MODULE, [Socket, Receiver]}) ->
    Req = <<?COM_QUERY, (iolist_to_binary(Query))/binary>>,
    SeqNum0 = 0,
    {ok, _SeqNum1} = send_packet(Socket, Req, SeqNum0),
    fetch_query_response(Receiver, Timeout).

%% @doc This is used by query/4. If query/4 returns {error, timeout}, this
%% function can be called to retry to fetch the results of the query. 
fetch_query_response(Receiver, Timeout) ->
    fetch_response(Receiver, Timeout, text, []).

%% @doc Prepares a statement.
-spec(prepare(iodata(), protocol()) -> #error{} | #prepared{}).
prepare(Query, {?MODULE, [Socket, Receiver]}) ->
    Req = <<?COM_STMT_PREPARE, (iolist_to_binary(Query))/binary>>,
    {ok, SeqNum1} = send_packet(Socket, Req, 0),
    {ok, Resp, SeqNum2} = recv_packet(Receiver, SeqNum1),
    case Resp of
        ?error_pattern ->
            mysql_parser:parse_error_packet(Resp);
        <<?OK,
          StmtId:32/little,
          NumColumns:16/little,
          NumParams:16/little,
          0, %% reserved_1 -- [00] filler
          WarningCount:16/little>> ->
            %% This was the first packet.
            %% Now: Parameter Definition Block. The parameter definitions don't
            %% contain any useful data at all. They are always TYPE_VAR_STRING
            %% with charset 'binary' so we have to select a type ourselves for
            %% the parameters we have in execute/4.
            {_ParamDefs, SeqNum3} =
                fetch_column_definitions_if_any(Receiver, NumParams, SeqNum2),
            %% Column Definition Block. We get column definitions in execute
            %% too, so we don't need them here. We *could* store them to be able
            %% to provide the user with some info about a prepared statement.
            {_ColDefs, _SeqNum4} =
                fetch_column_definitions_if_any(Receiver, NumColumns, SeqNum3),
            #prepared{statement_id = StmtId,
                      orig_query = Query,
                      param_count = NumParams,
                      warning_count = WarningCount}
    end.

%% @doc Deallocates a prepared statement.
-spec unprepare(#prepared{}, protocol()) -> ok.
unprepare(#prepared{statement_id = Id}, {?MODULE, [Socket, Receiver]}) ->
    {ok, _SeqNum} = send_packet(Socket, <<?COM_STMT_CLOSE, Id:32/little>>, 0),
    ok.

%% @doc Executes a prepared statement.
-spec execute(#prepared{}, [term()], timeout(), protocol()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
execute(#prepared{statement_id = Id, param_count = ParamCount}, ParamValues,
        Timeout, {?MODULE, [Socket, Receiver]}) when ParamCount == length(ParamValues) ->
    %% Flags Constant Name
    %% 0x00 CURSOR_TYPE_NO_CURSOR
    %% 0x01 CURSOR_TYPE_READ_ONLY
    %% 0x02 CURSOR_TYPE_FOR_UPDATE
    %% 0x04 CURSOR_TYPE_SCROLLABLE
    Flags = 0,
    Req0 = <<?COM_STMT_EXECUTE, Id:32/little, Flags, 1:32/little>>,
    Req = case ParamCount of
        0 ->
            Req0;
        _ ->
            %% We can't use the parameter types returned by the prepare call.
            %% They are all reported as ?TYPE_VAR_STRING with character
            %% set 'binary'.
            NullBitMap = build_null_bitmap(ParamValues),
            %% What does it mean to *not* bind new params? To use the same
            %% params as last time? Right now we always bind params each time.
            NewParamsBoundFlag = 1,
            Req1 = <<Req0/binary, NullBitMap/binary, NewParamsBoundFlag>>,
            %% For each value, first append type and signedness (16#80 signed or
            %% 00 unsigned) for all values and then the binary encoded values.
            EncodedParams = lists:map(fun encode_param/1, ParamValues),
            {TypesAndSigns, EncValues} = lists:unzip(EncodedParams),
            iolist_to_binary([Req1, TypesAndSigns, EncValues])
    end,
    {ok, _SeqNum1} = send_packet(Socket, Req, 0),
    fetch_execute_response(Receiver, Timeout).

%% @doc This is used by execute/5. If execute/5 returns {error, timeout}, this
%% function can be called to retry to fetch the results of the query.
fetch_execute_response(Receiver, Timeout) ->
    fetch_response(Receiver, Timeout, binary, []).



%% -- both text and binary protocol --

%% @doc Fetches one or more results and and parses the result set(s) using
%% either the text format (for plain queries) or the binary format (for
%% prepared statements).
-spec fetch_response(pid(), timeout(), text | binary, list()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
fetch_response(Receiver, Timeout, Proto, Acc) ->
    case recv_packet(Receiver, Timeout, any) of
        {ok, Packet, SeqNum2} ->
            Result = case Packet of
                ?ok_pattern ->
                    mysql_parser:parse_ok_packet(Packet);
                ?error_pattern ->
                    mysql_parser:parse_error_packet(Packet);
                ResultPacket ->
                    %% The first packet in a resultset is only the column count.
                    {ColCount, <<>>} = lenenc_int(ResultPacket),
                    R0 = fetch_resultset(Receiver, ColCount, SeqNum2),
                    case R0 of
                        #error{} = E ->
                            %% TODO: Find a way to get here + testcase
                            E;
                        #resultset{} = R ->
                            parse_resultset(R, ColCount, Proto)
                    end
            end,
            Acc1 = [Result | Acc],
            case more_results_exists(Result) of
                true ->
                    fetch_response(Receiver, Timeout, Proto, Acc1);
                false ->
                    {ok, lists:reverse(Acc1)}
            end;
        {error, timeout} ->
            {error, timeout}
    end.

%% @doc Fetches packets for a result set. The column definitions are parsed but
%% the rows are unparsed binary packages. This function is used for both the
%% text protocol and the binary protocol. This affects the way the rows need to
%% be parsed.
-spec fetch_resultset(pid(), integer(), integer()) ->
    #resultset{} | #error{}.
fetch_resultset(Receiver, FieldCount, SeqNum) ->
    {ok, ColDefs, SeqNum1} = fetch_column_definitions(Receiver, SeqNum, FieldCount, []),
    {ok, DelimiterPacket, SeqNum2} = recv_packet(TcpModule, Socket, SeqNum1),
    #eof{status = S, warning_count = W} = parse_eof_packet(DelimiterPacket),
    case fetch_resultset_rows(TcpModule, Socket, SeqNum2, []) of
        {ok, Rows, _SeqNum3} ->
            ColDefs1 = lists:map(fun parse_column_definition/1, ColDefs),
            #resultset{cols = ColDefs1, rows = Rows,
                       status = S, warning_count = W};
        #error{} = E ->
            E
    end.

more_results_exists(#ok{status = S}) ->
    S band ?SERVER_MORE_RESULTS_EXISTS /= 0;
more_results_exists(#error{}) ->
    false; %% No status bits for error
more_results_exists(#resultset{status = S}) ->
    S band ?SERVER_MORE_RESULTS_EXISTS /= 0.

%% @doc Receives NumLeft column definition packets. They are not parsed.
%% @see parse_column_definition/1
-spec(fetch_column_definitions(pid(), SeqNum :: integer(),
                               NumLeft :: integer(), Acc :: [binary()]) ->
    {ok, ColDefPackets :: [binary()], NextSeqNum :: integer()}).
fetch_column_definitions(Receiver, SeqNum, NumLeft, Acc)
  when NumLeft > 0 ->
    {ok, Packet, SeqNum1} = recv_packet(Receiver, SeqNum),
    fetch_column_definitions(Receiver, SeqNum1, NumLeft - 1,
                             [Packet | Acc]);
fetch_column_definitions(_Receiver, SeqNum, 0, Acc) ->
    {ok, lists:reverse(Acc), SeqNum}.

%% @doc Fetches rows in a result set. There is a packet per row. The row packets
%% are not decoded. This function can be used for both the binary and the text
%% protocol result sets.
-spec fetch_resultset_rows(pid(), SeqNum :: integer(), Acc) ->
    {ok, Rows, integer()} | #error{}
    when Acc :: [binary()],
         Rows :: [binary()].
fetch_resultset_rows(Receiver, SeqNum, Acc) ->
    {ok, Packet, SeqNum1} = recv_packet(Receiver, SeqNum),
    case Packet of
        ?error_pattern ->
            mysql_parser:parse_error_packet(Packet);
        ?eof_pattern ->
            {ok, lists:reverse(Acc), SeqNum1};
        Row ->
            fetch_resultset_rows(Receiver, SeqNum1, [Row | Acc])
    end.


%% -- binary protocol --

%% @doc If NumColumns is non-zero, fetches this number of column definitions
%% and an EOF packet. Used by prepare/3.
fetch_column_definitions_if_any(Receiver, 0, SeqNum) ->
    {[], SeqNum};
fetch_column_definitions_if_any(Receiver, N, SeqNum) ->
    {ok, Defs, SeqNum1} = fetch_column_definitions(Receiver, SeqNum, N, []),
    {ok, ?eof_pattern, SeqNum2} = recv_packet(Receiver, SeqNum1),
    {Defs, SeqNum2}.

%% @doc Used for executing prepared statements. The bit offset whould be 0 in
%% this case.
-spec build_null_bitmap([any()]) -> binary().
build_null_bitmap(Values) ->
    Bits = << <<(case V of null -> 1; _ -> 0 end):1>> || V <- Values >>,
    null_bitmap_encode(Bits, 0).

%% @doc Encodes a term reprenting av value as a binary for use in the binary
%% protocol. As this is used to encode parameters for prepared statements, the
%% encoding is in its required form, namely `<<Type:8, Sign:8, Value/binary>>'.
-spec encode_param(term()) -> {TypeAndSign :: binary(), Data :: binary()}.
encode_param(null) ->
    {<<?TYPE_NULL, 0>>, <<>>};
encode_param(Value) when is_binary(Value) ->
    EncLength = lenenc_int_encode(byte_size(Value)),
    {<<?TYPE_VAR_STRING, 0>>, <<EncLength/binary, Value/binary>>};
encode_param(Value) when is_list(Value) ->
    encode_param(unicode:characters_to_binary(Value));
encode_param(Value) when is_integer(Value), Value >= 0 ->
    %% We send positive integers with the 'unsigned' flag set.
    if
        Value =< 16#ff ->
            {<<?TYPE_TINY, 16#80>>, <<Value:8>>};
        Value =< 16#ffff ->
            {<<?TYPE_SHORT, 16#80>>, <<Value:16/little>>};
        Value =< 16#ffffffff ->
            {<<?TYPE_LONG, 16#80>>, <<Value:32/little>>};
        Value =< 16#ffffffffffffffff ->
            {<<?TYPE_LONGLONG, 16#80>>, <<Value:64/little>>};
        true ->
            %% If larger than a 64-bit int we send it as a string. MySQL does
            %% silently cast strings in aithmetic expressions. Also, DECIMALs
            %% are always sent as strings.
            encode_param(integer_to_binary(Value))
    end;
encode_param(Value) when is_integer(Value), Value < 0 ->
    if
        Value >= -16#80 ->
            {<<?TYPE_TINY, 0>>, <<Value:8>>};
        Value >= -16#8000 ->
            {<<?TYPE_SHORT, 0>>, <<Value:16/little>>};
        Value >= -16#80000000 ->
            {<<?TYPE_LONG, 0>>, <<Value:32/little>>};
        Value >= -16#8000000000000000 ->
            {<<?TYPE_LONGLONG, 0>>, <<Value:64/little>>};
        true ->
            encode_param(integer_to_binary(Value))
    end;
encode_param(Value) when is_float(Value) ->
    {<<?TYPE_DOUBLE, 0>>, <<Value:64/float-little>>};
encode_param(Value) when is_bitstring(Value) ->
    Binary = encode_bitstring(Value),
    EncLength = lenenc_int_encode(byte_size(Binary)),
    {<<?TYPE_VAR_STRING, 0>>, <<EncLength/binary, Binary/binary>>};
encode_param({Y, M, D}) ->
    %% calendar:date()
    {<<?TYPE_DATE, 0>>, <<4, Y:16/little, M, D>>};
encode_param({{Y, M, D}, {0, 0, 0}}) ->
    %% Datetime at midnight
    {<<?TYPE_DATETIME, 0>>, <<4, Y:16/little, M, D>>};
encode_param({{Y, M, D}, {H, Mi, S}}) when is_integer(S) ->
    %% calendar:datetime()
    {<<?TYPE_DATETIME, 0>>, <<7, Y:16/little, M, D, H, Mi, S>>};
encode_param({{Y, M, D}, {H, Mi, S}}) when is_float(S) ->
    %% calendar:datetime() with a float for seconds. This way it looks very
    %% similar to a datetime. Microseconds in MySQL timestamps are possible but
    %% not very common.
    Sec = trunc(S),
    Micro = round(1000000 * (S - Sec)),
    {<<?TYPE_DATETIME, 0>>, <<11, Y:16/little, M, D, H, Mi, Sec,
                              Micro:32/little>>};
encode_param({D, {H, M, S}}) when is_integer(S), D >= 0 ->
    %% calendar:seconds_to_daystime()
    {<<?TYPE_TIME, 0>>, <<8, 0, D:32/little, H, M, S>>};
encode_param({D, {H, M, S}}) when is_integer(S), D < 0 ->
    %% Convert to seconds, negate and convert back to daystime form.
    %% Then set the minus flag.
    Seconds = ((D * 24 + H) * 60 + M) * 60 + S,
    {D1, {H1, M1, S1}} = calendar:seconds_to_daystime(-Seconds),
    {<<?TYPE_TIME, 0>>, <<8, 1, D1:32/little, H1, M1, S1>>};
encode_param({D, {H, M, S}}) when is_float(S), D >= 0 ->
    S1 = trunc(S),
    Micro = round(1000000 * (S - S1)),
    {<<?TYPE_TIME, 0>>, <<12, 0, D:32/little, H, M, S1, Micro:32/little>>};
encode_param({D, {H, M, S}}) when is_float(S), S > 0.0, D < 0 ->
    IntS = trunc(S),
    Micro = round(1000000 * (1 - S + IntS)),
    Seconds = (D * 24 + H) * 3600 + M * 60 + IntS + 1,
    {D1, {M1, H1, S1}} = calendar:seconds_to_daystime(-Seconds),
    {<<?TYPE_TIME, 0>>, <<12, 1, D1:32/little, H1, M1, S1, Micro:32/little>>};
encode_param({D, {H, M, 0.0}}) ->
    encode_param({D, {H, M, 0}}).

%% -- Value representation in both the text and binary protocols --

%% @doc Convert to `<<_:Length/bitstring>>'
decode_bitstring(Binary, Length) ->
    PaddingLength = bit_size(Binary) - Length,
    <<_:PaddingLength/bitstring, Bitstring:Length/bitstring>> = Binary,
    Bitstring.

encode_bitstring(Bitstring) ->
    Size = bit_size(Bitstring),
    PaddingSize = byte_size(Bitstring) * 8 - Size,
    <<0:PaddingSize, Bitstring:Size/bitstring>>.

decode_decimal(Bin, _P, 0) ->
    binary_to_integer(Bin);
decode_decimal(Bin, P, S) when P =< 15, S > 0 ->
    binary_to_float(Bin);
decode_decimal(Bin, P, S) when P >= 16, S > 0 ->
    Bin.

%% -- Protocol basics: packets --

%% @doc Wraps Data in packet headers, sends it by calling TcpModule:send/2 with
%% Socket and returns {ok, SeqNum1} where SeqNum1 is the next sequence number.
-spec send_packet(mysql_sock:socket(), Packet :: binary(), SeqNum :: integer()) ->
    {ok, NextSeqNum :: integer()}.
send_packet(Socket, Packet, SeqNum) ->
    {WithHeaders, SeqNum1} = add_packet_headers(Packet, SeqNum),
    ok = mysql_sock:send(Socket, WithHeaders),
    {ok, SeqNum1}.

recv_packet(Receiver, SeqNum) ->
    recv_packet(Receiver, SeqNum, infinity).

recv_packet(Receiver, SeqNum, Timeout) when is_integer(SeqNum) ->
    NextSeqNum = SeqNum + 1,
    receive
        {mysql_recv, Receiver, {ok, NextSeqNum, Packet}} ->
            {ok, Packet, NextSeqNum};
        {'EXIT', Receiver, Reason} ->
            {error, Reason}
        after Timeout ->
            {error, mysql_timeout}
    end;

recv_packet(Receiver, _Any, Timeout) ->
    receive
        {mysql_recv, Receiver, {ok, SeqNum, Packet}} ->
            {ok, Packet, SeqNum};
        {'EXIT', Receiver, Reason} ->
            {error, Reason}
        after Timeout ->
            {error, mysql_timeout}
    end.

%% @doc Splits a packet body into chunks and wraps them in headers. The
%% resulting list is ready to sent to the socket.
-spec add_packet_headers(PacketBody :: iodata(), SeqNum :: integer()) ->
    {PacketWithHeaders :: iodata(), NextSeqNum :: integer()}.
add_packet_headers(PacketBody, SeqNum) ->
    Bin = iolist_to_binary(PacketBody),
    Size = size(Bin),
    SeqNum1 = (SeqNum + 1) band 16#ff,
    %% Todo: implement the case when Size >= 16#ffffff.
    if Size < 16#ffffff ->
        {[<<Size:24/little, SeqNum:8>>, Bin], SeqNum1}
    end.

-spec hash_password(Password :: iodata(), Salt :: binary()) -> Hash :: binary().
hash_password(Password, Salt) ->
    %% From the "MySQL Internals" manual:
    %% SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat>
    %%                            SHA1( SHA1( password ) ) )
    %% ----
    %% Make sure the salt is exactly 20 bytes.
    %%
    %% The auth data is obviously nul-terminated. For the "native" auth
    %% method, it should be a 20 byte salt, so let's trim it in this case.
    PasswordBin = case erlang:is_binary(Password) of
        true -> Password;
        false -> erlang:iolist_to_binary(Password)
    end,
    case PasswordBin =:= <<>> of
        true -> <<>>;
        false -> hash_non_empty_password(Password, Salt)
    end.

-spec hash_non_empty_password(Password :: iodata(), Salt :: binary()) -> Hash :: binary().
hash_non_empty_password(Password, Salt) ->
    Salt1 = case Salt of
        <<SaltNoNul:20/binary-unit:8, 0>> -> SaltNoNul;
        _ when size(Salt) == 20           -> Salt
    end,
    %% Hash as described above.
    <<Hash1Num:160>> = Hash1 = crypto:hash(sha, Password),
    Hash2 = crypto:hash(sha, Hash1),
    <<Hash3Num:160>> = crypto:hash(sha, <<Salt1/binary, Hash2/binary>>),
    <<(Hash1Num bxor Hash3Num):160>>.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Testing some of the internal functions, mostly the cases we don't cover in
%% other tests.

decode_text_test() ->
    %% Int types
    lists:foreach(fun (T) ->
                      ?assertEqual(1, decode_text(#col{type = T}, <<"1">>))
                  end,
                  [?TYPE_TINY, ?TYPE_SHORT, ?TYPE_LONG, ?TYPE_LONGLONG,
                   ?TYPE_INT24, ?TYPE_YEAR]),

    %% BIT
    <<217>> = decode_text(#col{type = ?TYPE_BIT, length = 8}, <<217>>),

    %% Floating point and decimal numbers
    lists:foreach(fun (T) ->
                      ?assertEqual(3.0, decode_text(#col{type = T}, <<"3.0">>))
                  end,
                  [?TYPE_FLOAT, ?TYPE_DOUBLE]),
    %% Decimal types
    lists:foreach(fun (T) ->
                      ColDef = #col{type = T, decimals = 1, length = 4},
                      ?assertMatch(3.0, decode_text(ColDef, <<"3.0">>))
                  end,
                  [?TYPE_DECIMAL, ?TYPE_NEWDECIMAL]),
    ?assertEqual(3.0,  decode_text(#col{type = ?TYPE_FLOAT}, <<"3">>)),
    ?assertEqual(30.0, decode_text(#col{type = ?TYPE_FLOAT}, <<"3e1">>)),
    ?assertEqual(3,    decode_text(#col{type = ?TYPE_LONG}, <<"3">>)),

    %% Date and time
    ?assertEqual({2014, 11, 01},
                 decode_text(#col{type = ?TYPE_DATE}, <<"2014-11-01">>)),
    ?assertEqual({0, {23, 59, 01}},
                 decode_text(#col{type = ?TYPE_TIME}, <<"23:59:01">>)),
    ?assertEqual({{2014, 11, 01}, {23, 59, 01}},
                 decode_text(#col{type = ?TYPE_DATETIME},
                             <<"2014-11-01 23:59:01">>)),
    ?assertEqual({{2014, 11, 01}, {23, 59, 01}},
                 decode_text(#col{type = ?TYPE_TIMESTAMP},
                             <<"2014-11-01 23:59:01">>)),

    %% Strings and blobs
    lists:foreach(fun (T) ->
                      ColDef = #col{type = T},
                      ?assertEqual(<<"x">>, decode_text(ColDef, <<"x">>))
                  end,
                  [?TYPE_VARCHAR, ?TYPE_ENUM, ?TYPE_TINY_BLOB,
                   ?TYPE_MEDIUM_BLOB, ?TYPE_LONG_BLOB, ?TYPE_BLOB,
                   ?TYPE_VAR_STRING, ?TYPE_STRING, ?TYPE_GEOMETRY]),
    ok.

decode_binary_test() ->
    %% Test the special rounding we apply to (single precision) floats.
    ?assertEqual({1.0, <<>>},
                 decode_binary(#col{type = ?TYPE_FLOAT},
                               <<1.0:32/float-little>>)),
    ?assertEqual({0.2, <<>>},
                 decode_binary(#col{type = ?TYPE_FLOAT},
                               <<0.2:32/float-little>>)),
    ?assertEqual({-33.3333, <<>>},
                 decode_binary(#col{type = ?TYPE_FLOAT},
                               <<-33.333333:32/float-little>>)),
    ?assertEqual({0.000123457, <<>>},
                 decode_binary(#col{type = ?TYPE_FLOAT},
                               <<0.00012345678:32/float-little>>)),
    ?assertEqual({1234.57, <<>>},
                 decode_binary(#col{type = ?TYPE_FLOAT},
                               <<1234.56789:32/float-little>>)),
    ok.

null_bitmap_test() ->
    ?assertEqual({<<0, 1:1>>, <<>>}, null_bitmap_decode(9, <<0, 4>>, 2)),
    ?assertEqual(<<0, 4>>, null_bitmap_encode(<<0, 1:1>>, 2)),
    ok.

add_packet_headers_test() ->
    {Data, 43} = add_packet_headers(<<"foo">>, 42),
    ?assertEqual(<<3, 0, 0, 42, "foo">>, list_to_binary(Data)).

hash_password_test() ->
    ?assertEqual(<<222,207,222,139,41,181,202,13,191,241,
                   234,234,73,127,244,101,205,3,28,251>>,
                 hash_password(<<"foo">>, <<"abcdefghijklmnopqrst">>)),
    ?assertEqual(<<>>, hash_password(<<>>, <<"abcdefghijklmnopqrst">>)).

-endif.
