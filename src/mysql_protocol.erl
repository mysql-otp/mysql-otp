%% This module implements parts of the MySQL client/server protocol.
%%
%% The protocol is described in the document "MySQL Internals" which can be
%% found under "MySQL Documentation: Expert Guides" on http://dev.mysql.com/
%%
%% TCP communication is not handled in this module. Most of the public functions
%% take funs for data communitaction as parameters.
-module(mysql_protocol).

-export([handshake/5,
         query/3]).

-export_type([sendfun/0, recvfun/0]).

-type sendfun() :: fun((binary()) -> ok).
-type recvfun() :: fun((integer()) -> {ok, binary()}).

%% How much data do we want to send at most?
-define(MAX_BYTES_PER_PACKET, 50000000).

-include("records.hrl").
-include("protocol.hrl").

%% Macros for pattern matching on packets.
-define(ok_pattern, <<?OK, _/binary>>).
-define(error_pattern, <<?ERROR, _/binary>>).
-define(eof_pattern, <<?EOF, _:4/binary>>).

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
    SeqNum1 = (SeqNum + 1) rem 16#100,
    %% Todo: implement the case when Size >= 16#ffffff.
    if Size < 16#ffffff ->
        {[<<Size:24/little, SeqNum:8>>, Bin], SeqNum1}
    end.

%% @doc Performs a handshake using the supplied functions for communication.
%% Returns an ok or an error record. Raises errors when various unimplemented
%% features are requested.
%%
%% TODO: Implement setting the database in the handshake. Currently an error
%% occurs if Database is anything other than undefined.
-spec handshake(iodata(), iodata(), iodata() | undefined, sendfun(),
                recvfun()) -> #ok{} | #error{}.
handshake(Username, Password, Database, SendFun, RecvFun) ->
    SeqNum0 = 0,
    Database == undefined orelse error(database_in_handshake),
    {ok, HandshakePacket, SeqNum1} = recv_packet(RecvFun, SeqNum0),
    Handshake = parse_handshake(HandshakePacket),
    Response = build_handshake_response(Handshake, Username, Password),
    {ok, SeqNum2} = send_packet(SendFun, Response, SeqNum1),
    {ok, ConfirmPacket, _SeqNum3} = recv_packet(RecvFun, SeqNum2),
    parse_handshake_confirm(ConfirmPacket).

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
        0 -> 13;    %% if not CLIENT_PLUGIN_AUTH
        K -> K - 8
    end,
    <<AuthPluginDataPart2:Len/binary-unit:8, AuthPluginName/binary>> = Rest3,
    AuthPluginData = <<AuthPluginDataPart1/binary, AuthPluginDataPart2/binary>>,
    %% "Due to Bug#59453 the auth-plugin-name is missing the terminating
    %% NUL-char in versions prior to 5.5.10 and 5.6.2."
    %% Strip the final NUL byte if any.
    NameLen = size(AuthPluginName) - 1,
    AuthPluginName1 = case AuthPluginName of
        <<NameNoNul:NameLen/binary-unit:8, 0>> -> NameNoNul;
        _ -> AuthPluginName
    end,
    #handshake{server_version = ServerVersion,
              connection_id = ConnectionId,
              capabilities = Capabilities,
              character_set = CharacterSet,
              status = StatusFlags,
              auth_plugin_data = AuthPluginData,
              auth_plugin_name = AuthPluginName1};
parse_handshake(<<Protocol:8, _/binary>>) when Protocol /= 10 ->
    error(unknown_protocol).

%% @doc The response sent by the client to the server after receiving the
%% initial handshake from the server
-spec build_handshake_response(#handshake{}, iodata(), iodata()) -> binary().
build_handshake_response(Handshake, Username, Password) ->
    %% We require these capabilities. Make sure the server handles them.
    CapabilityFlags = ?CLIENT_PROTOCOL_41 bor
                      ?CLIENT_TRANSACTIONS bor
                      ?CLIENT_SECURE_CONNECTION,
    Handshake#handshake.capabilities band CapabilityFlags == CapabilityFlags
        orelse error(old_server_version),
    Hash = hash_password(Password,
                         Handshake#handshake.auth_plugin_name,
                         Handshake#handshake.auth_plugin_data),
    HashLength = size(Hash),
    CharacterSet = ?UTF8,
    UsernameUtf8 = unicode:characters_to_binary(Username),
    <<CapabilityFlags:32/little,
      ?MAX_BYTES_PER_PACKET:32/little,
      CharacterSet:8,
      0:23/unit:8, %% reserverd
      UsernameUtf8/binary,
      0, %% NUL-terminator for the username
      HashLength,
      Hash/binary>>.

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
            %% "Insufficient Client Capabilities"
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

%% @doc Normally fun gen_tcp:send/2 and fun gen_tcp:recv/3 are used, except in
%% unit testing.
query(Query, SendFun, RecvFun) ->
    Req = <<?COM_QUERY, (iolist_to_binary(Query))/binary>>,
    SeqNum0 = 0,
    {ok, SeqNum1} = send_packet(SendFun, Req, SeqNum0),
    {ok, Resp, SeqNum2} = recv_packet(RecvFun, SeqNum1),
    case Resp of
        ?ok_pattern ->
            parse_ok_packet(Resp);
        ?error_pattern ->
            parse_error_packet(Resp);
        _ResultSet ->
            %% The first packet in a resultset is just the field count.
            {FieldCount, <<>>} = lenenc_int(Resp),
            fetch_resultset(RecvFun, FieldCount, SeqNum2)
    end.

prepare(Query, SendFun, RecvFun) ->
    Req = <<?COM_STMT_PREPARE, (iolist_to_binary(Query))/binary>>,
    {ok, SeqNum1} = send_packet(SendFun, Req, 0),
    {ok, Resp, SeqNum2} = recv_packet(RecvFun, SeqNum1),

-spec fetch_resultset(recvfun(), integer(), integer()) ->
    #text_resultset{} | #error{}.
fetch_resultset(RecvFun, FieldCount, SeqNum) ->
    {ok, ColDefs, SeqNum1} = fetch_column_definitions(RecvFun, SeqNum,
                                                      FieldCount, []),
    {ok, DelimiterPacket, SeqNum2} = recv_packet(RecvFun, SeqNum1),
    case DelimiterPacket of
        ?eof_pattern ->
            #eof{} = parse_eof_packet(DelimiterPacket),
            {ok, Rows, _SeqNum3} = fetch_resultset_rows(RecvFun, ColDefs,
                                                        SeqNum2, []),
            #text_resultset{column_definitions = ColDefs, rows = Rows};
        ?error_pattern ->
            parse_error_packet(DelimiterPacket)
    end.

%% Receives NumLeft packets and parses them as column definitions.
-spec fetch_column_definitions(recvfun(), SeqNum :: integer(),
                               NumLeft :: integer(), Acc :: [tuple()]) ->
    {ok, [tuple()], NextSeqNum :: integer()}.
fetch_column_definitions(RecvFun, SeqNum, NumLeft, Acc) when NumLeft > 0 ->
    {ok, Packet, SeqNum1} = recv_packet(RecvFun, SeqNum),
    ColDef = parse_column_definition(Packet),
    fetch_column_definitions(RecvFun, SeqNum1, NumLeft - 1, [ColDef | Acc]);
fetch_column_definitions(_RecvFun, SeqNum, 0, Acc) ->
    {ok, lists:reverse(Acc), SeqNum}.

fetch_resultset_rows(RecvFun, ColDefs, SeqNum, Acc) ->
    {ok, Packet, SeqNum1} = recv_packet(RecvFun, SeqNum),
    case Packet of
        ?eof_pattern ->
            {ok, lists:reverse(Acc), SeqNum1};
        _AnotherRow ->
            Row = parse_resultset_row(ColDefs, Packet, []),
            fetch_resultset_rows(RecvFun, ColDefs, SeqNum1, [Row | Acc])
    end.

%% parses Data using ColDefs and builds the values Acc.
parse_resultset_row([_ColDef | ColDefs], Data, Acc) ->
    case Data of
        <<16#fb, Rest/binary>> ->
            %% NULL
            parse_resultset_row(ColDefs, Rest, [null | Acc]);
        _ ->
            %% Every thing except NULL
            {Str, Rest} = lenenc_str(Data),
            parse_resultset_row(ColDefs, Rest, [Str | Acc])
    end;
parse_resultset_row([], <<>>, Acc) ->
    lists:reverse(Acc).

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
      _ColumnLength:32/little,  %% maximum length of the field
      ColumnType:8,             %% type of the column as defined in Column Type
      _Flags:16/little,         %% flags
      _Decimals:8,              %% max shown decimal digits:
      0,  %% "filler"           %%   - 0x00 for integers and static strings
      0,                        %%   - 0x1f for dynamic strings, double, float
      Rest8/binary>> = Rest7,   %%   - 0x00 to 0x51 for decimals
    %% Here, if command was COM_FIELD_LIST {
    %%   default values: lenenc_str
    %% }
    <<>> = Rest8,
    #column_definition{name = Name, type = ColumnType, charset = Charset}.

%% --- internal ---

%% @doc Wraps Data in packet headers, sends it by calling SendFun and returns
%% {ok, SeqNum1} where SeqNum1 is the next sequence number.
-spec send_packet(sendfun(), Data :: binary(), SeqNum :: integer()) ->
    {ok, NextSeqNum :: integer()}.
send_packet(SendFun, Data, SeqNum) ->
    {WithHeaders, SeqNum1} = add_packet_headers(Data, SeqNum),
    ok = SendFun(WithHeaders),
    {ok, SeqNum1}.

%% @doc Receives data by calling RecvFun and removes the packet headers. Returns
%% the packet contents and the next packet sequence number.
-spec recv_packet(RecvFun :: recvfun(), SeqNum :: integer()) ->
    {ok, Data :: binary(), NextSeqNum :: integer()}.
recv_packet(RecvFun, SeqNum) ->
    recv_packet(RecvFun, SeqNum, <<>>).

%% @doc Receives data by calling RecvFun and removes packet headers. Returns the
%% data and the next packet sequence number.
-spec recv_packet(RecvFun :: recvfun(), ExpectSeqNum :: integer(),
                  Acc :: binary()) ->
    {ok, Data :: binary(), NextSeqNum :: integer()}.
recv_packet(RecvFun, ExpectSeqNum, Acc) ->
    {ok, Header} = RecvFun(4),
    {Size, ExpectSeqNum, More} = parse_packet_header(Header),
    {ok, Body} = RecvFun(Size),
    Acc1 = <<Acc/binary, Body/binary>>,
    NextSeqNum = (ExpectSeqNum + 1) band 16#ff,
    case More of
        false -> {ok, Acc1, NextSeqNum};
        true  -> recv_packet(RecvFun, NextSeqNum, Acc1)
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

-spec hash_password(Password :: iodata(), AuthPluginName :: binary(),
                    AuthPluginData :: binary()) -> binary().
hash_password(_Password, <<"mysql_old_password">>, _Salt) ->
    error(old_auth);
hash_password(Password, <<"mysql_native_password">>, AuthData) ->
    %% From the "MySQL Internals" manual:
    %% SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat>
    %%                            SHA1( SHA1( password ) ) )
    %% ----
    %% Make sure the salt is exactly 20 bytes.
    %%
    %% The auth data is obviously nul-terminated. For the "native" auth
    %% method, it should be a 20 byte salt, so let's trim it in this case.
    Salt = case AuthData of
        <<SaltNoNul:20/binary-unit:8, 0>> -> SaltNoNul;
        _ when size(AuthData) == 20       -> AuthData
    end,
    %% Hash as described above.
    <<Hash1Num:160>> = Hash1 = crypto:hash(sha, Password),
    Hash2 = crypto:hash(sha, Hash1),
    <<Hash3Num:160>> = crypto:hash(sha, <<Salt/binary, Hash2/binary>>),
    <<(Hash1Num bxor Hash3Num):160>>;
hash_password(_, AuthPlugin, _) ->
    error({auth_method, AuthPlugin}).

%% lenenc_int/1 decodes length-encoded-integer values
-spec lenenc_int(Input :: binary()) -> {Value :: integer(), Rest :: binary()}.
lenenc_int(<<Value:8, Rest/bits>>) when Value < 251 -> {Value, Rest};
lenenc_int(<<16#fc:8, Value:16/little, Rest/binary>>) -> {Value, Rest};
lenenc_int(<<16#fd:8, Value:24/little, Rest/binary>>) -> {Value, Rest};
lenenc_int(<<16#fe:8, Value:64/little, Rest/binary>>) -> {Value, Rest}.

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

lenenc_int_test() ->
    ?assertEqual({40, <<>>}, lenenc_int(<<40>>)),
    ?assertEqual({16#ff, <<>>}, lenenc_int(<<16#fc, 255, 0>>)),
    ?assertEqual({16#33aaff, <<>>}, lenenc_int(<<16#fd, 16#ff, 16#aa, 16#33>>)),
    ?assertEqual({16#12345678, <<>>}, lenenc_int(<<16#fe, 16#78, 16#56, 16#34,
                                                 16#12, 0, 0, 0, 0>>)),
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


-endif.
