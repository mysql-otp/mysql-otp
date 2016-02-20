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

-export([handshake/5, quit/2, ping/2,
         query/4, fetch_query_response/3,
         prepare/3, unprepare/3, execute/5, fetch_execute_response/3]).

%% How much data do we want per packet?
-define(MAX_BYTES_PER_PACKET, 16#1000000).

-include("records.hrl").
-include("protocol.hrl").
-include("server_status.hrl").

%% Macros for pattern matching on packets.
-define(ok_pattern, <<?OK, _/binary>>).
-define(error_pattern, <<?ERROR, _/binary>>).
-define(eof_pattern, <<?EOF, _:4/binary>>).

%% @doc Performs a handshake using the supplied functions for communication.
%% Returns an ok or an error record. Raises errors when various unimplemented
%% features are requested.
-spec handshake(iodata(), iodata(), iodata() | undefined, atom(), term()) ->
    #handshake{} | #error{}.
handshake(Username, Password, Database, TcpModule, Socket) ->
    SeqNum0 = 0,
    {ok, HandshakePacket, SeqNum1} = recv_packet(TcpModule, Socket, SeqNum0),
    Handshake = parse_handshake(HandshakePacket),
    Response = build_handshake_response(Handshake, Username, Password,
                                        Database),
    {ok, SeqNum2} = send_packet(TcpModule, Socket, Response, SeqNum1),
    {ok, ConfirmPacket, _SeqNum3} = recv_packet(TcpModule, Socket, SeqNum2),
    case parse_handshake_confirm(ConfirmPacket) of
        #ok{status = OkStatus} ->
            OkStatus = Handshake#handshake.status,
            Handshake;
        Error ->
            Error
    end.

-spec quit(atom(), term()) -> ok.
quit(TcpModule, Socket) ->
    {ok, SeqNum1} = send_packet(TcpModule, Socket, <<?COM_QUIT>>, 0),
    case recv_packet(TcpModule, Socket, SeqNum1) of
        {error, closed} -> ok;            %% MySQL 5.5.40 and more
        {ok, ?ok_pattern, _SeqNum2} -> ok %% Some older MySQL versions?
    end.

-spec ping(atom(), term()) -> #ok{}.
ping(TcpModule, Socket) ->
    {ok, SeqNum1} = send_packet(TcpModule, Socket, <<?COM_PING>>, 0),
    {ok, OkPacket, _SeqNum2} = recv_packet(TcpModule, Socket, SeqNum1),
    parse_ok_packet(OkPacket).

-spec query(Query :: iodata(), atom(), term(), timeout()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
query(Query, TcpModule, Socket, Timeout) ->
    Req = <<?COM_QUERY, (iolist_to_binary(Query))/binary>>,
    SeqNum0 = 0,
    {ok, _SeqNum1} = send_packet(TcpModule, Socket, Req, SeqNum0),
    fetch_query_response(TcpModule, Socket, Timeout).

%% @doc This is used by query/4. If query/4 returns {error, timeout}, this
%% function can be called to retry to fetch the results of the query. 
fetch_query_response(TcpModule, Socket, Timeout) ->
    fetch_response(TcpModule, Socket, Timeout, text, []).

%% @doc Prepares a statement.
-spec prepare(iodata(), atom(), term()) -> #error{} | #prepared{}.
prepare(Query, TcpModule, Socket) ->
    Req = <<?COM_STMT_PREPARE, (iolist_to_binary(Query))/binary>>,
    {ok, SeqNum1} = send_packet(TcpModule, Socket, Req, 0),
    {ok, Resp, SeqNum2} = recv_packet(TcpModule, Socket, SeqNum1),
    case Resp of
        ?error_pattern ->
            parse_error_packet(Resp);
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
                fetch_column_definitions_if_any(NumParams, TcpModule, Socket,
                                                SeqNum2),
            %% Column Definition Block. We get column definitions in execute
            %% too, so we don't need them here. We *could* store them to be able
            %% to provide the user with some info about a prepared statement.
            {_ColDefs, _SeqNum4} =
                fetch_column_definitions_if_any(NumColumns, TcpModule, Socket,
                                                SeqNum3),
            #prepared{statement_id = StmtId,
                      orig_query = Query,
                      param_count = NumParams,
                      warning_count = WarningCount}
    end.

%% @doc Deallocates a prepared statement.
-spec unprepare(#prepared{}, atom(), term()) -> ok.
unprepare(#prepared{statement_id = Id}, TcpModule, Socket) ->
    {ok, _SeqNum} = send_packet(TcpModule, Socket,
                                <<?COM_STMT_CLOSE, Id:32/little>>, 0),
    ok.

%% @doc Executes a prepared statement.
-spec execute(#prepared{}, [term()], atom(), term(), timeout()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
execute(#prepared{statement_id = Id, param_count = ParamCount}, ParamValues,
        TcpModule, Socket, Timeout) when ParamCount == length(ParamValues) ->
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
    {ok, _SeqNum1} = send_packet(TcpModule, Socket, Req, 0),
    fetch_execute_response(TcpModule, Socket, Timeout).

%% @doc This is used by execute/5. If execute/5 returns {error, timeout}, this
%% function can be called to retry to fetch the results of the query.
fetch_execute_response(TcpModule, Socket, Timeout) ->
    fetch_response(TcpModule, Socket, Timeout, binary, []).

%% --- internal ---

%% @doc Parses a handshake. This is the first thing that comes from the server
%% when connecting. If an unsupported version or variant of the protocol is used
%% an error is raised.
-spec parse_handshake(binary()) -> #handshake{}.
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

%% @doc The response sent by the client to the server after receiving the
%% initial handshake from the server
-spec build_handshake_response(#handshake{}, iodata(), iodata(),
                               iodata() | undefined) -> binary().
build_handshake_response(Handshake, Username, Password, Database) ->
    %% We require these capabilities. Make sure the server handles them.
    CapabilityFlags0 = ?CLIENT_PROTOCOL_41 bor
                       ?CLIENT_TRANSACTIONS bor
                       ?CLIENT_SECURE_CONNECTION,
    CapabilityFlags = case Database of
        undefined -> CapabilityFlags0;
        _         -> CapabilityFlags0 bor ?CLIENT_CONNECT_WITH_DB
    end,
    Handshake#handshake.capabilities band CapabilityFlags == CapabilityFlags
        orelse error(old_server_version),
    %% Add some extra capability flags only for signalling to the server what
    %% the client wants to do. The server doesn't say it handles them although
    %% it does. (http://bugs.mysql.com/bug.php?id=42268)
    ClientCapabilityFlags = CapabilityFlags bor
                            ?CLIENT_MULTI_STATEMENTS bor
                            ?CLIENT_MULTI_RESULTS bor
                            ?CLIENT_PS_MULTI_RESULTS,
    Hash = case Handshake#handshake.auth_plugin_name of
        <<>> ->
            %% Server doesn't know auth plugins
            hash_password(Password, Handshake#handshake.auth_plugin_data);
        <<"mysql_native_password">> ->
            hash_password(Password, Handshake#handshake.auth_plugin_data);
        UnknownAuthMethod ->
            error({auth_method, UnknownAuthMethod})
    end,
    HashLength = size(Hash),
    CharacterSet = ?UTF8,
    UsernameUtf8 = unicode:characters_to_binary(Username),
    DbBin = case Database of
        undefined -> <<>>;
        _         -> <<(iolist_to_binary(Database))/binary, 0>>
    end,
    <<ClientCapabilityFlags:32/little,
      ?MAX_BYTES_PER_PACKET:32/little,
      CharacterSet:8,
      0:23/unit:8, %% reserverd
      UsernameUtf8/binary,
      0, %% NUL-terminator for the username
      HashLength,
      Hash/binary,
      DbBin/binary>>.

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

%% -- both text and binary protocol --

%% @doc Fetches one or more results and and parses the result set(s) using
%% either the text format (for plain queries) or the binary format (for
%% prepared statements).
-spec fetch_response(atom(), term(), timeout(), text | binary, list()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
fetch_response(TcpModule, Socket, Timeout, Proto, Acc) ->
    case recv_packet(TcpModule, Socket, Timeout, any) of
        {ok, Packet, SeqNum2} ->
            Result = case Packet of
                ?ok_pattern ->
                    parse_ok_packet(Packet);
                ?error_pattern ->
                    parse_error_packet(Packet);
                ResultPacket ->
                    %% The first packet in a resultset is only the column count.
                    {ColCount, <<>>} = lenenc_int(ResultPacket),
                    R0 = fetch_resultset(TcpModule, Socket, ColCount, SeqNum2),
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
                    fetch_response(TcpModule, Socket, Timeout, Proto, Acc1);
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
-spec fetch_resultset(atom(), term(), integer(), integer()) ->
    #resultset{} | #error{}.
fetch_resultset(TcpModule, Socket, FieldCount, SeqNum) ->
    {ok, ColDefs, SeqNum1} = fetch_column_definitions(TcpModule, Socket, SeqNum,
                                                      FieldCount, []),
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

parse_resultset(#resultset{cols = ColDefs, rows = Rows} = R, ColumnCount, text) ->
    %% Parse the rows according to the 'text protocol' representation.
    Rows1 = [decode_text_row(ColumnCount, ColDefs, Row) || Row <- Rows],
    R#resultset{rows = Rows1};
parse_resultset(#resultset{cols = ColDefs, rows = Rows} = R, ColumnCount, binary) ->
    %% Parse the rows according to the 'binary protocol' representation.
    Rows1 = [decode_binary_row(ColumnCount, ColDefs, Row) || Row <- Rows],
    R#resultset{rows = Rows1}.

more_results_exists(#ok{status = S}) ->
    S band ?SERVER_MORE_RESULTS_EXISTS /= 0;
more_results_exists(#error{}) ->
    false; %% No status bits for error
more_results_exists(#resultset{status = S}) ->
    S band ?SERVER_MORE_RESULTS_EXISTS /= 0.

%% @doc Receives NumLeft column definition packets. They are not parsed.
%% @see parse_column_definition/1
-spec fetch_column_definitions(atom(), term(), SeqNum :: integer(),
                               NumLeft :: integer(), Acc :: [binary()]) ->
    {ok, ColDefPackets :: [binary()], NextSeqNum :: integer()}.
fetch_column_definitions(TcpModule, Socket, SeqNum, NumLeft, Acc)
  when NumLeft > 0 ->
    {ok, Packet, SeqNum1} = recv_packet(TcpModule, Socket, SeqNum),
    fetch_column_definitions(TcpModule, Socket, SeqNum1, NumLeft - 1,
                             [Packet | Acc]);
fetch_column_definitions(_TcpModule, _Socket, SeqNum, 0, Acc) ->
    {ok, lists:reverse(Acc), SeqNum}.

%% @doc Fetches rows in a result set. There is a packet per row. The row packets
%% are not decoded. This function can be used for both the binary and the text
%% protocol result sets.
-spec fetch_resultset_rows(atom(), term(), SeqNum :: integer(), Acc) ->
    {ok, Rows, integer()} | #error{}
    when Acc :: [binary()],
         Rows :: [binary()].
fetch_resultset_rows(TcpModule, Socket, SeqNum, Acc) ->
    {ok, Packet, SeqNum1} = recv_packet(TcpModule, Socket, SeqNum),
    case Packet of
        ?error_pattern ->
            parse_error_packet(Packet);
        ?eof_pattern ->
            {ok, lists:reverse(Acc), SeqNum1};
        Row ->
            fetch_resultset_rows(TcpModule, Socket, SeqNum1, [Row | Acc])
    end.

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

%% @doc If NumColumns is non-zero, fetches this number of column definitions
%% and an EOF packet. Used by prepare/3.
fetch_column_definitions_if_any(0, _TcpModule, _Socket, SeqNum) ->
    {[], SeqNum};
fetch_column_definitions_if_any(N, TcpModule, Socket, SeqNum) ->
    {ok, Defs, SeqNum1} = fetch_column_definitions(TcpModule, Socket, SeqNum,
                                                   N, []),
    {ok, ?eof_pattern, SeqNum2} = recv_packet(TcpModule, Socket, SeqNum1),
    {Defs, SeqNum2}.

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

%% @doc Used for executing prepared statements. The bit offset whould be 0 in
%% this case.
-spec build_null_bitmap([any()]) -> binary().
build_null_bitmap(Values) ->
    Bits = << <<(case V of null -> 1; _ -> 0 end):1>> || V <- Values >>,
    null_bitmap_encode(Bits, 0).

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
-spec send_packet(atom(), term(), Data :: binary(), SeqNum :: integer()) ->
    {ok, NextSeqNum :: integer()}.
send_packet(TcpModule, Socket, Data, SeqNum) ->
    {WithHeaders, SeqNum1} = add_packet_headers(Data, SeqNum),
    ok = TcpModule:send(Socket, WithHeaders),
    {ok, SeqNum1}.

%% @see recv_packet/4
recv_packet(TcpModule, Socket, SeqNum) ->
    recv_packet(TcpModule, Socket, infinity, SeqNum).

%% @doc Receives data by calling TcpModule:recv/2 and removes the packet
%% headers. Returns the packet contents and the next packet sequence number.
-spec recv_packet(atom(), term(), timeout(), integer() | any) ->
    {ok, Data :: binary(), NextSeqNum :: integer()} | {error, term()}.
recv_packet(TcpModule, Socket, Timeout, SeqNum) ->
    recv_packet(TcpModule, Socket, Timeout, SeqNum, <<>>).

%% @doc Accumulating helper for recv_packet/4
-spec recv_packet(atom(), term(), timeout(), integer() | any, binary()) ->
    {ok, Data :: binary(), NextSeqNum :: integer()} | {error, term()}.
recv_packet(TcpModule, Socket, Timeout, ExpectSeqNum, Acc) ->
    case TcpModule:recv(Socket, 4, Timeout) of
        {ok, Header} ->
            {Size, SeqNum, More} = parse_packet_header(Header),
            true = SeqNum == ExpectSeqNum orelse ExpectSeqNum == any,
            {ok, Body} = TcpModule:recv(Socket, Size),
            Acc1 = <<Acc/binary, Body/binary>>,
            NextSeqNum = (SeqNum + 1) band 16#ff,
            case More of
                false -> {ok, Acc1, NextSeqNum};
                true  -> recv_packet(TcpModule, Socket, Timeout, NextSeqNum,
                                     Acc1)
            end;
        {error, Reason} ->
            {error, Reason}
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
-spec parse_packet_header(PackerHeader :: binary()) ->
    {PacketLength :: integer(),
     SeqNum :: integer(),
     MorePacketsExist :: boolean()}.
parse_packet_header(<<PacketLength:24/little-integer, SeqNum:8/integer>>) ->
    {PacketLength, SeqNum, PacketLength == 16#ffffff}.

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

parse_header_test() ->
    %% Example from "MySQL Internals", revision 307, section 14.1.3.3 EOF_Packet
    Packet = <<16#05, 16#00, 16#00, 16#05, 16#fe, 16#00, 16#00, 16#02, 16#00>>,
    <<Header:4/binary-unit:8, Body/binary>> = Packet,
    %% Check header contents and body length
    ?assertEqual({size(Body), 5, false}, parse_packet_header(Header)),
    ok.

add_packet_headers_test() ->
    {Data, 43} = add_packet_headers(<<"foo">>, 42),
    ?assertEqual(<<3, 0, 0, 42, "foo">>, list_to_binary(Data)).

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

hash_password_test() ->
    ?assertEqual(<<222,207,222,139,41,181,202,13,191,241,
                   234,234,73,127,244,101,205,3,28,251>>,
                 hash_password(<<"foo">>, <<"abcdefghijklmnopqrst">>)),
    ?assertEqual(<<>>, hash_password(<<>>, <<"abcdefghijklmnopqrst">>)).

-endif.
