%% This module implements parts of the MySQL client/server protocol.
%%
%% The protocol is described in the document "MySQL Internals" which can be
%% found under "MySQL Documentation: Expert Guides" on http://dev.mysql.com/
%%
%% TCP communication is not handled in this module.
-module(mysql_protocol).

-export([parse_packet_header/1, add_packet_headers/2,
         parse_handshake/1, build_handshake_response/3,
         parse_handshake_confirm/1,
         build_query/1, parse_query_response/1]).

-include("records.hrl").
-include("protocol.hrl").

%% How much data do we want to send at most?
-define(MAX_BYTES_PER_PACKET, 50000000).

%% Macros for pattern matching on packets.
-define(ok_pattern, <<?OK, _/binary>>).
-define(error_pattern, <<?ERROR, _/binary>>).
-define(eof_pattern, <<?EOF, _/binary>>).

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

%% @doc Parses a handshake. This is the first thing that comes from the server
%% when connecting. If an unsupported version of variant of the protocol is used
%% an error is raised.
-spec parse_handshake(binary()) -> #handshake{}.
parse_handshake(<<10, Rest/binary>>) ->
    %% Protocol version 10.
    {ServerVersion, Rest1} = nulterm(Rest),
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
        orelse error({incompatible, <<"Server version is too old">>}),
    Hash = hash_password(Password,
                         Handshake#handshake.auth_plugin_name,
                         Handshake#handshake.auth_plugin_data),
    HashLength = size(Hash),
    CharacterSet = 16#21, %% utf8_general_ci
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
%% initial handshake. Returns an error if unimplemented features are required.
-spec parse_handshake_confirm(binary()) -> #ok_packet{} | #error_packet{}.
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
            %%
            %% Simulate an error packet (without code)
            #error_packet{msg = <<"Old auth method not implemented">>};
        <<?EOF, _/binary>> ->
            %% "Authentication Method Switch Request Packet. If both server and
            %% client support CLIENT_PLUGIN_AUTH capability, server can send
            %% this packet to ask client to use another authentication method."
            %%
            %% Simulate an error packet (without code)
            #error_packet{msg = <<"Auth method switch not implemented">>}
    end.

build_query(Query) when is_binary(Query) ->
    <<?COM_QUERY, Query/binary>>.

%% @doc TODO: Handle result set responses.
-spec parse_query_response(binary()) -> #ok_packet{} | #error_packet{}.
parse_query_response(Resp) ->
    case Resp of
        ?ok_pattern -> parse_ok_packet(Resp);
        ?error_pattern -> parse_error_packet(Resp);
        _ -> error(result_set_not_implemented)
    end.

%% --- internal ---

%is_ok_packet(<<?OK, _/binary>>) -> true;
%is_ok_packet(_)                 -> false;

%is_error_packet(<<?ERROR, _/binary>>) -> true;
%is_error_packet(_)                    -> false;

%is_eof_packet(<<?EOF, _/binary>>) -> true;
%is_eof_paclet(_)                  -> false;

-spec parse_ok_packet(binary()) -> #ok_packet{}.
parse_ok_packet(<<?OK:8, Rest/binary>>) ->
    {AffectedRows, Rest1} = lci(Rest),
    {InsertId, Rest2} = lci(Rest1),
    <<StatusFlags:16/little, WarningCount:16/little, Msg/binary>> = Rest2,
    %% We have enabled CLIENT_PROTOCOL_41 but not CLIENT_SESSION_TRACK in the
    %% conditional protocol:
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
    #ok_packet{affected_rows = AffectedRows,
               insert_id = InsertId,
               status = StatusFlags,
               warning_count = WarningCount,
               msg = Msg}.

-spec parse_error_packet(binary()) -> #error_packet{}.
parse_error_packet(<<?ERROR:8, ErrNo:16/little, "#", SQLState:5/binary-unit:8,
                     Msg/binary>>) ->
    %% Error, 4.1 protocol.
    %% (Older protocol: <<?ERROR:8, ErrNo:16/little, Msg/binary>>)
    #error_packet{code = ErrNo, state = SQLState, msg = Msg}.

-spec parse_eof_packet(binary()) -> #eof_packet{}.
parse_eof_packet(<<?EOF:8, NumWarnings:16/little, StatusFlags:16/little>>) ->
    %% EOF packet, 4.1 protocol.
    %% (Older protocol: <<?EOF:8>>)
    #eof_packet{status = StatusFlags, warning_count = NumWarnings}.

-spec hash_password(Password :: iodata(), AuthPluginName :: binary(),
                    AuthPluginData :: binary()) -> binary().
hash_password(_Password, <<"mysql_old_password">>, _Salt) ->
    error({incompatible, <<"Old auth method not implemented">>});
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
    error({unsupported_auth_method, AuthPlugin}).

%% lci/1 decodes length-coded-integer values
-spec lci(Input :: binary()) -> {Value :: integer(), Rest :: binary()}.
lci(<<Value:8, Rest/bits>>) when Value < 251 -> {Value, Rest};
lci(<<16#fc:8, Value:16/little, Rest/binary>>) -> {Value, Rest};
lci(<<16#fd:8, Value:24/little, Rest/binary>>) -> {Value, Rest};
lci(<<16#fe:8, Value:64/little, Rest/binary>>) -> {Value, Rest}.

%% lcs/1 decodes length-encoded-string values
-spec lcs(Input :: binary()) -> {String :: binary(), Rest :: binary()}.
lcs(Bin) ->
    {Length, Rest} = lci(Bin),
    <<String:Length/binary, Rest1/binary>> = Rest,
    {String, Rest1}.

%% nts/1 decodes a nul-terminated string
-spec nulterm(Input :: binary()) -> {String :: binary(), Rest :: binary()}.
nulterm(Bin) ->
    [String, Rest] = binary:split(Bin, <<0>>),
    {String, Rest}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

lci_test() ->
    ?assertEqual({40, <<>>}, lci(<<40>>)),
    ?assertEqual({16#ff, <<>>}, lci(<<16#fc, 255, 0>>)),
    ?assertEqual({16#33aaff, <<>>}, lci(<<16#fd, 16#ff, 16#aa, 16#33>>)),
    ?assertEqual({16#12345678, <<>>}, lci(<<16#fe, 16#78, 16#56, 16#34, 16#12,
                                            0, 0, 0, 0>>)),
    ok.

lcs_test() ->
    ?assertEqual({<<"Foo">>, <<"bar">>}, lcs(<<3, "Foobar">>)).

nulterm_test() ->
    ?assertEqual({<<"Foo">>, <<"bar">>}, nulterm(<<"Foo", 0, "bar">>)).

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
    ?assertEqual(#ok_packet{affected_rows = 5,
                            insert_id = 1,
                            status = ?SERVER_STATUS_AUTOCOMMIT,
                            warning_count = 0,
                            msg = <<"Foo">>},
                 parse_ok_packet(Body)).

parse_error_test() ->
    %% Protocol 4.1
    Body = <<255, 42, 0, "#", "XYZxx", "Foo">>,
    ?assertEqual(#error_packet{code = 42,
                               state = <<"XYZxx">>,
                               msg = <<"Foo">>},
                 parse_error_packet(Body)),
    ok.

parse_eof_test() ->
    %% Example from "MySQL Internals", revision 307, section 14.1.3.3 EOF_Packet
    Packet = <<16#05, 16#00, 16#00, 16#05, 16#fe, 16#00, 16#00, 16#02, 16#00>>,
    <<_Header:4/binary-unit:8, Body/binary>> = Packet,
    %% Ignore header. Parse body as an eof_packet.
    ?assertEqual(#eof_packet{warning_count = 0,
                             status = ?SERVER_STATUS_AUTOCOMMIT},
                 parse_eof_packet(Body)),
    ok.

-endif.
