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

%% @doc MySQL Packet Parser
%%
%% This module parses MySQL packets received from Server.

-module(mysql_parser).

-author("Feng Lee <feng@emqtt.io>").

-include("protocol.hrl").

-include("records.hrl").

-export([new/0]).

-export([parse_handshake/1, parse_handshake_confirm/1, parse_ok_packet/1, parse_eof_packet/1,
         parse_error_packet/1, parse_column_definition/1]).

-type(parse_fun() :: fun((binary()) -> {ok, byte(), binary(), binary()} | {more, parse_fun()})).

%% @doc Initialize a parser
-spec(new() -> parse_fun()).
new() -> fun(Bin) -> parse(Bin, none) end.

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
parse(<<>>, none) ->
    {more, fun(Bin) -> parse(Bin, none) end};

parse(Bin, none) when size(Bin) < 4 ->
    {more, fun(More) -> parse(<<Bin/binary, More/binary>>, none) end};

parse(<<Len:24/little, Seq:8, Bin/binary>>, none) ->
    parse_body(Bin, Seq, Len).

parse_body(Bin, Seq, Len) when size(Bin) < Len ->
    {more, fun(More) -> parse_body(<<Bin/binary, More/binary>>, Seq, Len) end};

parse_body(Bin, Seq, Len) ->
    <<Body:Len/binary, Rest/binary>> = Bin, {ok, Seq, Body, Rest}.

%% @doc Parses a handshake. This is the first thing that comes from the server
%% when connecting. If an unsupported version or variant of the protocol is used
%% an error is raised.
-spec(parse_handshake(binary()) -> #handshake{}).
parse_handshake(<<10, Rest/binary>>) ->
    %% Protocol version 10.
    {ServerVersion, Rest1} = nulterm_str(Rest),
    <<ConnectionId:32/little,
      AuthPluginDataPart1:8/binary-unit:8,
      0, %% "filler" -- everything below is optional
      CapabilitiesLower:16/little,
      CharacterSet:8,
      StatusFlags:16/little,
      CapabilitiesUpper:16/little,
      AuthPluginDataLength:8,     %% if cabab & CLIENT_PLUGIN_AUTH, otherwise 0
      _Reserved:10/binary-unit:8, %% 10 unused (reserved) bytes
      Rest3/binary>> = Rest1,
    Capabilities = CapabilitiesLower + 16#10000 * CapabilitiesUpper,
    Len = case AuthPluginDataLength of
        0 -> 13;   %% Server has not CLIENT_PLUGIN_AUTH
        K -> K - 8 %% Part 2 length = Total length minus the 8 bytes in part 1.
    end,
    <<AuthPluginDataPart2:Len/binary-unit:8, AuthPluginName/binary>> = Rest3,
    AuthPluginData = <<AuthPluginDataPart1/binary, AuthPluginDataPart2/binary>>,
    %% "Due to Bug#59453 the auth-plugin-name is missing the terminating
    %% NUL-char in versions prior to 5.5.10 and 5.6.2."
    %% Strip the final NUL byte if any.
    %% This may also be <<>> in older versions.
    L = byte_size(AuthPluginName) - 1,
    AuthPluginName1 = case AuthPluginName of
        <<AuthPluginNameTrimmed:L/binary, 0>> -> AuthPluginNameTrimmed;
        _ -> AuthPluginName
    end,
    #handshake{server_version = server_version_to_list(ServerVersion),
               connection_id = ConnectionId,
               capabilities = Capabilities,
               character_set = CharacterSet,
               status = StatusFlags,
               auth_plugin_data = AuthPluginData,
               auth_plugin_name = AuthPluginName1};
parse_handshake(<<Protocol:8, _/binary>>) when Protocol /= 10 ->
    error(unknown_protocol).

%% @doc Converts a version on the form `<<"5.6.21">' to a list `[5, 6, 21]'.
-spec server_version_to_list(binary()) -> [integer()].
server_version_to_list(ServerVersion) ->
    %% This must work with e.g. "5.5.40-0ubuntu0.12.04.1-log" and "5.5.33a".
    {match, Parts} = re:run(ServerVersion, <<"^(\\d+)\\.(\\d+)\\.(\\d+)">>,
                            [{capture, all_but_first, binary}]),
    lists:map(fun binary_to_integer/1, Parts).

%% @doc Handles the second packet from the server, when we have replied to the
%% initial handshake. Returns an error if the server returns an error. Raises
%% an error if unimplemented features are required.
-spec parse_handshake_confirm(binary()) -> #ok{} | #error{}.
parse_handshake_confirm(Packet) ->
    case Packet of
        ?ok_pattern ->
            %% Connection complete.
            parse_ok_packet(Packet);
        ?error_pattern ->
            %% Access denied, insufficient client capabilities, etc.
            parse_error_packet(Packet);
        <<?EOF>> ->
            %% "Old Authentication Method Switch Request Packet consisting of a
            %% single 0xfe byte. It is sent by server to request client to
            %% switch to Old Password Authentication if CLIENT_PLUGIN_AUTH
            %% capability is not supported (by either the client or the server)"
            error(old_auth);
        <<?EOF, _/binary>> ->
            %% "Authentication Method Switch Request Packet. If both server and
            %% client support CLIENT_PLUGIN_AUTH capability, server can send
            %% this packet to ask client to use another authentication method."
            error(auth_method_switch)
    end.

-spec parse_ok_packet(binary()) -> #ok{}.
parse_ok_packet(<<?OK:8, Rest/binary>>) ->
    {AffectedRows, Rest1} = lenenc_int(Rest),
    {InsertId, Rest2} = lenenc_int(Rest1),
    <<StatusFlags:16/little, WarningCount:16/little, Msg/binary>> = Rest2,
    %% We have CLIENT_PROTOCOL_41 but not CLIENT_SESSION_TRACK enabled. The
    %% protocol is conditional. This is from the protocol documentation:
    %%
    %% if capabilities & CLIENT_PROTOCOL_41 {
    %%   int<2> status_flags
    %%   int<2> warning_count
    %% } elseif capabilities & CLIENT_TRANSACTIONS {
    %%   int<2> status_flags
    %% }
    %% if capabilities & CLIENT_SESSION_TRACK {
    %%   string<lenenc> info
    %%   if status_flags & SERVER_SESSION_STATE_CHANGED {
    %%     string<lenenc> session_state_changes
    %%   }
    %% } else {
    %%   string<EOF> info
    %% }
    #ok{affected_rows = AffectedRows,
        insert_id = InsertId,
        status = StatusFlags,
        warning_count = WarningCount,
        msg = Msg}.

-spec parse_error_packet(binary()) -> #error{}.
parse_error_packet(<<?ERROR:8, ErrNo:16/little, "#", SQLState:5/binary-unit:8,
                     Msg/binary>>) ->
    %% Error, 4.1 protocol.
    %% (Older protocol: <<?ERROR:8, ErrNo:16/little, Msg/binary>>)
    #error{code = ErrNo, state = SQLState, msg = Msg}.

-spec parse_eof_packet(binary()) -> #eof{}.
parse_eof_packet(<<?EOF:8, NumWarnings:16/little, StatusFlags:16/little>>) ->
    %% EOF packet, 4.1 protocol.
    %% (Older protocol: <<?EOF:8>>)
    #eof{status = StatusFlags, warning_count = NumWarnings}.

parse_resultset(#resultset{cols = ColDefs, rows = Rows} = R, ColumnCount, text) ->
    %% Parse the rows according to the 'text protocol' representation.
    Rows1 = [decode_text_row(ColumnCount, ColDefs, Row) || Row <- Rows],
    R#resultset{rows = Rows1};
parse_resultset(#resultset{cols = ColDefs, rows = Rows} = R, ColumnCount, binary) ->
    %% Parse the rows according to the 'binary protocol' representation.
    Rows1 = [decode_binary_row(ColumnCount, ColDefs, Row) || Row <- Rows],
    R#resultset{rows = Rows1}.

%% Parses a packet containing a column definition (part of a result set)
parse_column_definition(Data) ->
    {<<"def">>, Rest1} = lenenc_str(Data),   %% catalog (always "def")
    {_Schema, Rest2} = lenenc_str(Rest1),    %% schema-name 
    {_Table, Rest3} = lenenc_str(Rest2),     %% virtual table-name 
    {_OrgTable, Rest4} = lenenc_str(Rest3),  %% physical table-name 
    {Name, Rest5} = lenenc_str(Rest4),       %% virtual column name
    {_OrgName, Rest6} = lenenc_str(Rest5),   %% physical column name
    {16#0c, Rest7} = lenenc_int(Rest6),      %% length of the following fields
                                             %% (always 0x0c)
    <<Charset:16/little,        %% column character set
      Length:32/little,         %% maximum length of the field
      Type:8,                   %% type of the column as defined in Column Type
      Flags:16/little,          %% flags
      Decimals:8,               %% max shown decimal digits:
      0,  %% "filler"           %%   - 0x00 for integers and static strings
      0,                        %%   - 0x1f for dynamic strings, double, float
      Rest8/binary>> = Rest7,   %%   - 0x00 to 0x51 for decimals
    %% Here, if command was COM_FIELD_LIST {
    %%   default values: lenenc_str
    %% }
    <<>> = Rest8,
    #col{name = Name, type = Type, charset = Charset, length = Length,
         decimals = Decimals, flags = Flags}.

%% -- text protocol --

-spec decode_text_row(NumColumns :: integer(),
                      ColumnDefinitions :: [#col{}],
                      Data :: binary()) -> [term()].
decode_text_row(_NumColumns, ColumnDefs, Data) ->
    decode_text_row_acc(ColumnDefs, Data, []).

%% parses Data using ColDefs and builds the values Acc.
decode_text_row_acc([ColDef | ColDefs], Data, Acc) ->
    case Data of
        <<16#fb, Rest/binary>> ->
            %% NULL
            decode_text_row_acc(ColDefs, Rest, [null | Acc]);
        _ ->
            %% Every thing except NULL
            {Text, Rest} = lenenc_str(Data),
            Term = decode_text(ColDef, Text),
            decode_text_row_acc(ColDefs, Rest, [Term | Acc])
    end;
decode_text_row_acc([], <<>>, Acc) ->
    lists:reverse(Acc).

%% @doc When receiving data in the text protocol, we get everything as binaries
%% (except NULL). This function is used to parse these string values.
decode_text(#col{type = T}, Text)
  when T == ?TYPE_TINY; T == ?TYPE_SHORT; T == ?TYPE_LONG; T == ?TYPE_LONGLONG;
       T == ?TYPE_INT24; T == ?TYPE_YEAR ->
    binary_to_integer(Text);
decode_text(#col{type = T}, Text)
  when T == ?TYPE_STRING; T == ?TYPE_VARCHAR; T == ?TYPE_VAR_STRING;
       T == ?TYPE_ENUM; T == ?TYPE_SET; T == ?TYPE_LONG_BLOB;
       T == ?TYPE_MEDIUM_BLOB; T == ?TYPE_BLOB; T == ?TYPE_TINY_BLOB;
       T == ?TYPE_GEOMETRY ->
    %% As of MySQL 5.6.21 we receive SET and ENUM values as STRING, i.e. we
    %% cannot convert them to atom() or sets:set(), etc.
    Text;
decode_text(#col{type = ?TYPE_BIT, length = Length}, Text) ->
    %% Convert to <<_:Length/bitstring>>
    decode_bitstring(Text, Length);
decode_text(#col{type = T, decimals = S, length = L}, Text)
  when T == ?TYPE_DECIMAL; T == ?TYPE_NEWDECIMAL ->
    %% Length is the max number of symbols incl. dot and minus sign, e.g. the
    %% number of digits plus 2.
    decode_decimal(Text, L - 2, S);
decode_text(#col{type = ?TYPE_DATE},
            <<Y:4/binary, "-", M:2/binary, "-", D:2/binary>>) ->
    {binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)};
decode_text(#col{type = ?TYPE_TIME}, Text) ->
    {match, [Sign, Hbin, Mbin, Sbin, Frac]} =
        re:run(Text,
               <<"^(-?)(\\d+):(\\d+):(\\d+)(\\.?\\d*)$">>,
               [{capture, all_but_first, binary}]),
    H = binary_to_integer(Hbin),
    M = binary_to_integer(Mbin),
    S = binary_to_integer(Sbin),
    IsNeg = Sign == <<"-">>,
    Fraction = case Frac of
        <<>> -> 0;
        _ when not IsNeg -> binary_to_float(<<"0", Frac/binary>>);
        _ when IsNeg -> 1 - binary_to_float(<<"0", Frac/binary>>)
    end,
    Sec1 = H * 3600 + M * 60 + S,
    Sec2 = if IsNeg -> -Sec1; true -> Sec1 end,
    Sec3 = if IsNeg and (Fraction /= 0) -> Sec2 - 1;
              true                      -> Sec2
           end,
    {Days, {Hours, Minutes, Seconds}} = calendar:seconds_to_daystime(Sec3),
    {Days, {Hours, Minutes, Seconds + Fraction}};
decode_text(#col{type = T},
            <<Y:4/binary, "-", M:2/binary, "-", D:2/binary, " ",
              H:2/binary, ":", Mi:2/binary, ":", S:2/binary>>)
  when T == ?TYPE_TIMESTAMP; T == ?TYPE_DATETIME ->
    %% Without fractions.
    {{binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)},
     {binary_to_integer(H), binary_to_integer(Mi), binary_to_integer(S)}};
decode_text(#col{type = T},
            <<Y:4/binary, "-", M:2/binary, "-", D:2/binary, " ",
              H:2/binary, ":", Mi:2/binary, ":", FloatS/binary>>)
  when T == ?TYPE_TIMESTAMP; T == ?TYPE_DATETIME ->
    %% With fractions.
    {{binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)},
     {binary_to_integer(H), binary_to_integer(Mi), binary_to_float(FloatS)}};
decode_text(#col{type = T}, Text) when T == ?TYPE_FLOAT;
                                                     T == ?TYPE_DOUBLE ->
    try binary_to_float(Text)
    catch error:badarg ->
        try binary_to_integer(Text) of
            Int -> float(Int)
        catch error:badarg ->
            %% It is something like "4e75" that must be turned into "4.0e75"
            binary_to_float(binary:replace(Text, <<"e">>, <<".0e">>))
        end
    end.

%% -- binary protocol --

%% @doc Decodes a packet representing a row in a binary result set.
%% It consists of a 0 byte, then a null bitmap, then the values.
%% Returns a list of length NumColumns with terms of appropriate types for each
%% MySQL type in ColumnTypes.
-spec decode_binary_row(NumColumns :: integer(),
                        ColumnDefs :: [#col{}],
                        Data :: binary()) -> [term()].
decode_binary_row(NumColumns, ColumnDefs, <<0, Data/binary>>) ->
    {NullBitMap, Rest} = null_bitmap_decode(NumColumns, Data, 2),
    decode_binary_row_acc(ColumnDefs, NullBitMap, Rest, []).

%% @doc Accumulating helper for decode_binary_row/3.
decode_binary_row_acc([_|ColDefs], <<1:1, NullBitMap/bitstring>>, Data, Acc) ->
    %% NULL
    decode_binary_row_acc(ColDefs, NullBitMap, Data, [null | Acc]);
decode_binary_row_acc([ColDef | ColDefs], <<0:1, NullBitMap/bitstring>>, Data,
                      Acc) ->
    %% Not NULL
    {Term, Rest} = decode_binary(ColDef, Data),
    decode_binary_row_acc(ColDefs, NullBitMap, Rest, [Term | Acc]);
decode_binary_row_acc([], _, <<>>, Acc) ->
    lists:reverse(Acc).

%% @doc Decodes a null bitmap as stored by MySQL and returns it in a strait
%% bitstring counting bits from left to right in a tuple with remaining data.
%%
%% In the MySQL null bitmap the bits are stored counting bytes from the left and
%% bits within each byte from the right. (Sort of little endian.)
-spec null_bitmap_decode(NumColumns :: integer(), Data :: binary(),
                         BitOffset :: integer()) ->
    {NullBitstring :: bitstring(), Rest :: binary()}.
null_bitmap_decode(NumColumns, Data, BitOffset) ->
    %% Binary shift right by 3 is equivallent to integer division by 8.
    BitMapLength = (NumColumns + BitOffset + 7) bsr 3,
    <<NullBitstring0:BitMapLength/binary, Rest/binary>> = Data,
    <<_:BitOffset, NullBitstring:NumColumns/bitstring, _/bitstring>> =
        << <<(reverse_byte(B))/binary>> || <<B:1/binary>> <= NullBitstring0 >>,
    {NullBitstring, Rest}.

%% @doc The reverse of null_bitmap_decode/3. The number of columns is taken to
%% be the number of bits in NullBitstring. Returns the MySQL null bitmap as a
%% binary (i.e. full bytes). BitOffset is the number of unused bits that should
%% be inserted before the other bits.
-spec null_bitmap_encode(bitstring(), integer()) -> binary().
null_bitmap_encode(NullBitstring, BitOffset) ->
    PayloadLength = bit_size(NullBitstring) + BitOffset,
    %% Round up to a multiple of 8.
    BitMapLength = (PayloadLength + 7) band bnot 7,
    PadBitsLength = BitMapLength - PayloadLength,
    PaddedBitstring = <<0:BitOffset, NullBitstring/bitstring, 0:PadBitsLength>>,
    << <<(reverse_byte(B))/binary>> || <<B:1/binary>> <= PaddedBitstring >>.

%% Reverses the bits in a byte.
reverse_byte(<<A:1, B:1, C:1, D:1, E:1, F:1, G:1, H:1>>) ->
    <<H:1, G:1, F:1, E:1, D:1, C:1, B:1, A:1>>.

%% Decodes a value as received in the 'binary protocol' result set.
%%
%% The types are type constants for the binary protocol, such as
%% ProtocolBinary::MYSQL_TYPE_STRING. In the guide "MySQL Internals" these are
%% not listed, but we assume that are the same as for the text protocol.
-spec decode_binary(ColDef :: #col{}, Data :: binary()) ->
    {Term :: term(), Rest :: binary()}.
decode_binary(#col{type = T}, Data)
  when T == ?TYPE_STRING; T == ?TYPE_VARCHAR; T == ?TYPE_VAR_STRING;
       T == ?TYPE_ENUM; T == ?TYPE_SET; T == ?TYPE_LONG_BLOB;
       T == ?TYPE_MEDIUM_BLOB; T == ?TYPE_BLOB; T == ?TYPE_TINY_BLOB;
       T == ?TYPE_GEOMETRY ->
    %% As of MySQL 5.6.21 we receive SET and ENUM values as STRING, i.e. we
    %% cannot convert them to atom() or sets:set(), etc.
    lenenc_str(Data);
decode_binary(#col{type = ?TYPE_LONGLONG},
              <<Value:64/signed-little, Rest/binary>>) ->
    {Value, Rest};
decode_binary(#col{type = T}, <<Value:32/signed-little, Rest/binary>>)
  when T == ?TYPE_LONG; T == ?TYPE_INT24 ->
    {Value, Rest};
decode_binary(#col{type = T}, <<Value:16/signed-little, Rest/binary>>)
  when T == ?TYPE_SHORT; T == ?TYPE_YEAR ->
    {Value, Rest};
decode_binary(#col{type = ?TYPE_TINY}, <<Value:8/signed, Rest/binary>>) ->
    {Value, Rest};
decode_binary(#col{type = T, decimals = S, length = L}, Data)
  when T == ?TYPE_DECIMAL; T == ?TYPE_NEWDECIMAL ->
    %% Length is the max number of symbols incl. dot and minus sign, e.g. the
    %% number of digits plus 2.
    {Binary, Rest} = lenenc_str(Data),
    {decode_decimal(Binary, L - 2, S), Rest};
decode_binary(#col{type = ?TYPE_DOUBLE},
              <<Value:64/float-little, Rest/binary>>) ->
    {Value, Rest};
decode_binary(#col{type = ?TYPE_FLOAT}, <<0.0:32/float-little, Rest/binary>>) ->
    %% TYPE_FLOAT conversation fails on math:log10(0.0)
    {0.0, Rest};
decode_binary(#col{type = ?TYPE_FLOAT},
              <<Value:32/float-little, Rest/binary>>) ->
    %% There is a precision loss when storing and fetching a 32-bit float.
    %% In the text protocol, it is obviously rounded. Storing 3.14 in a FLOAT
    %% column and fetching it using the text protocol, we get "3.14" which we
    %% parse to the Erlang double as close as possible to 3.14. Fetching the
    %% same value as a binary 32-bit float, we get 3.140000104904175. To achieve
    %% the same rounding after receiving it as a 32-bit float, we try to do the
    %% same rounding here as MySQL does when sending it over the text protocol.
    %%
    %% This comment explains the idea:
    %%
    %%     Posted by Geoffrey Downs on March 10 2011 10:26am
    %%
    %%     Following up... I *think* this is correct for the default float
    %%     columns in mysql:
    %%
    %%     var yourNumber = some floating point value
    %%     max decimal precision = 10 ^ (-5 + floor(yourNumber log 10))
    %%     So:
    %%     0 < x < 10 -> max precision is 0.00001
    %%     10 <= x < 100 -> max precision is 0.0001
    %%     100 <= x < 1000 -> max precision is 0.001
    %%     etc.
    %%
    %% (From http://dev.mysql.com/doc/refman/5.7/en/problems-with-float.html
    %% fetched 10 Nov 2014)
    %%
    %% The above is almost correct, except for the example in the interval
    %% 0 < x < 1. There are 6 significant digits also for these numbers.
    %%
    %% Now, instead of P = 0.00001 we want the inverse 100000.0 but if we
    %% compute Factor = 1 / P we get a precision loss, so instead we do this:
    Factor = math:pow(10, floor(6 - math:log10(abs(Value)))),
    RoundedValue = round(Value * Factor) / Factor,
    {RoundedValue, Rest};
decode_binary(#col{type = ?TYPE_BIT, length = Length}, Data) ->
    {Binary, Rest} = lenenc_str(Data),
    %% Convert to <<_:Length/bitstring>>
    {decode_bitstring(Binary, Length), Rest};
decode_binary(#col{type = ?TYPE_DATE}, <<Length, Data/binary>>) ->
    %% Coded in the same way as DATETIME and TIMESTAMP below, but returned in
    %% a simple triple.
    case {Length, Data} of
        {0, _} -> {{0, 0, 0}, Data};
        {4, <<Y:16/little, M, D, Rest/binary>>} -> {{Y, M, D}, Rest}
    end;
decode_binary(#col{type = T}, <<Length, Data/binary>>)
  when T == ?TYPE_DATETIME; T == ?TYPE_TIMESTAMP ->
    %% length (1) -- number of bytes following (valid values: 0, 4, 7, 11)
    case {Length, Data} of
        {0, _} ->
            {{{0, 0, 0}, {0, 0, 0}}, Data};
        {4, <<Y:16/little, M, D, Rest/binary>>} ->
            {{{Y, M, D}, {0, 0, 0}}, Rest};
        {7, <<Y:16/little, M, D, H, Mi, S, Rest/binary>>} ->
            {{{Y, M, D}, {H, Mi, S}}, Rest};
        {11, <<Y:16/little, M, D, H, Mi, S, Micro:32/little, Rest/binary>>} ->
            {{{Y, M, D}, {H, Mi, S + 0.000001 * Micro}}, Rest}
    end;
decode_binary(#col{type = ?TYPE_TIME}, <<Length, Data/binary>>) ->
    %% length (1) -- number of bytes following (valid values: 0, 8, 12)
    %% is_negative (1) -- (1 if minus, 0 for plus)
    %% days (4) -- days
    %% hours (1) -- hours
    %% minutes (1) -- minutes
    %% seconds (1) -- seconds
    %% micro_seconds (4) -- micro-seconds
    case {Length, Data} of
        {0, _} ->
            {{0, {0, 0, 0}}, Data};
        {8, <<0, D:32/little, H, M, S, Rest/binary>>} ->
            {{D, {H, M, S}}, Rest};
        {12, <<0, D:32/little, H, M, S, Micro:32/little, Rest/binary>>} ->
            {{D, {H, M, S + 0.000001 * Micro}}, Rest};
        {8, <<1, D:32/little, H, M, S, Rest/binary>>} ->
            %% Negative time. Example: '-00:00:01' --> {-1,{23,59,59}}
            Seconds = ((D * 24 + H) * 60 + M) * 60 + S,
            %Seconds = D * 86400 + calendar:time_to_seconds({H, M, S}),
            {calendar:seconds_to_daystime(-Seconds), Rest};
        {12, <<1, D:32/little, H, M, S, Micro:32/little, Rest/binary>>}
          when Micro > 0 ->
            %% Negate and convert to seconds, excl fractions
            Seconds = -(((D * 24 + H) * 60 + M) * 60 + S),
            %Seconds = -D * 86400 - calendar:time_to_seconds({H, M, S}),
            %% Subtract 1 second for the fractions
            {Days, {Hours, Minutes, Sec}} =
                calendar:seconds_to_daystime(Seconds - 1),
            %% Adding the fractions to Sec again makes it a float
            {{Days, {Hours, Minutes, Sec + 1 - 0.000001 * Micro}}, Rest}
    end.

%% @doc Like trunc/1 but towards negative infinity instead of towards zero.
floor(Value) ->
    Trunc = trunc(Value),
    if
        Trunc =< Value -> Trunc;
        Trunc > Value -> Trunc - 1 %% for negative values
    end.

%% --- Lowlevel: variable length integers and strings ---

%% lenenc_int/1 decodes length-encoded-integer values
-spec lenenc_int(Input :: binary()) -> {Value :: integer(), Rest :: binary()}.
lenenc_int(<<Value:8, Rest/bits>>) when Value < 251 -> {Value, Rest};
lenenc_int(<<16#fc:8, Value:16/little, Rest/binary>>) -> {Value, Rest};
lenenc_int(<<16#fd:8, Value:24/little, Rest/binary>>) -> {Value, Rest};
lenenc_int(<<16#fe:8, Value:64/little, Rest/binary>>) -> {Value, Rest}.

%% Length-encoded-integer encode. Appends the encoded value to Acc.
%% Values not representable in 64 bits are not accepted.
-spec lenenc_int_encode(0..16#ffffffffffffffff) -> binary().
lenenc_int_encode(Value) when Value >= 0 ->
    if Value < 251 -> <<Value>>;
       Value =< 16#ffff -> <<16#fc, Value:16/little>>;
       Value =< 16#ffffff -> <<16#fd, Value:24/little>>;
       Value =< 16#ffffffffffffffff -> <<16#fe, Value:64/little>>
    end.

%% lenenc_str/1 decodes length-encoded-string values
-spec lenenc_str(Input :: binary()) -> {String :: binary(), Rest :: binary()}.
lenenc_str(Bin) ->
    {Length, Rest} = lenenc_int(Bin),
    <<String:Length/binary, Rest1/binary>> = Rest,
    {String, Rest1}.

%% nts/1 decodes a nul-terminated string
-spec nulterm_str(Input :: binary()) -> {String :: binary(), Rest :: binary()}.
nulterm_str(Bin) ->
    [String, Rest] = binary:split(Bin, <<0>>),
    {String, Rest}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

parse_header_test() ->
    Parser = new(),
    %% Example from "MySQL Internals", revision 307, section 14.1.3.3 EOF_Packet
    {ok, Packet, SeqNum} = Parser(<<16#05, 16#00, 16#00, 16#05, 16#fe, 16#00, 16#00, 16#02, 16#00>>),
    %% Check header contents and body length
    ?assertEqual({5, 5}, {SeqNum, size(Packet)}),
    ok.

parse_ok_test() ->
    Body = <<0, 5, 1, 2, 0, 0, 0, "Foo">>,
    ?assertEqual(#ok{affected_rows = 5,
                     insert_id = 1,
                     status = ?SERVER_STATUS_AUTOCOMMIT,
                     warning_count = 0,
                     msg = <<"Foo">>},
                 parse_ok_packet(Body)).

parse_error_test() ->
    %% Protocol 4.1
    Body = <<255, 42, 0, "#", "XYZxx", "Foo">>,
    ?assertEqual(#error{code = 42, state = <<"XYZxx">>, msg = <<"Foo">>},
                 parse_error_packet(Body)),
    ok.

parse_eof_test() ->
    %% Example from "MySQL Internals", revision 307, section 14.1.3.3 EOF_Packet
    Packet = <<16#05, 16#00, 16#00, 16#05, 16#fe, 16#00, 16#00, 16#02, 16#00>>,
    <<_Header:4/binary-unit:8, Body/binary>> = Packet,
    %% Ignore header. Parse body as an eof_packet.
    ?assertEqual(#eof{warning_count = 0,
                      status = ?SERVER_STATUS_AUTOCOMMIT},
                 parse_eof_packet(Body)),
    ok.

lenenc_int_test() ->
    %% decode
    ?assertEqual({40, <<>>}, lenenc_int(<<40>>)),
    ?assertEqual({16#ff, <<>>}, lenenc_int(<<16#fc, 255, 0>>)),
    ?assertEqual({16#33aaff, <<>>}, lenenc_int(<<16#fd, 16#ff, 16#aa, 16#33>>)),
    ?assertEqual({16#12345678, <<>>}, lenenc_int(<<16#fe, 16#78, 16#56, 16#34,
                                                 16#12, 0, 0, 0, 0>>)),
    %% encode
    ?assertEqual(<<40>>, lenenc_int_encode(40)),
    ?assertEqual(<<16#fc, 255, 0>>, lenenc_int_encode(255)),
    ?assertEqual(<<16#fd, 16#ff, 16#aa, 16#33>>,
                 lenenc_int_encode(16#33aaff)),
    ?assertEqual(<<16#fe, 16#78, 16#56, 16#34, 16#12, 0, 0, 0, 0>>,
                 lenenc_int_encode(16#12345678)),
    ok.

lenenc_str_test() ->
    ?assertEqual({<<"Foo">>, <<"bar">>}, lenenc_str(<<3, "Foobar">>)).

nulterm_test() ->
    ?assertEqual({<<"Foo">>, <<"bar">>}, nulterm_str(<<"Foo", 0, "bar">>)).

-endif.


