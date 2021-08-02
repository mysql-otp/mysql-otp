%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014-2021 Viktor Söderqvist
%%               2017 Piotr Nosek, Michal Slaski
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

-export([handshake/8, change_user/8, quit/2, ping/2,
         query/6, fetch_query_response/5, prepare/3, unprepare/3,
         execute/7, fetch_execute_response/5, reset_connnection/2,
         valid_params/1, valid_path/1]).

-type query_filtermap() :: no_filtermap_fun | mysql:query_filtermap_fun().

-type auth_more_data() :: fast_auth_completed
                        | full_auth_requested
                        | {public_key, term()}.

%% How much data do we want per packet?
-define(MAX_BYTES_PER_PACKET, 16#1000000).

-include_lib("public_key/include/public_key.hrl").

-include("records.hrl").
-include("protocol.hrl").
-include("server_status.hrl").

%% Macros for pattern matching on packets.
-define(ok_pattern, <<?OK, _/binary>>).
-define(error_pattern, <<?ERROR, _/binary>>).
-define(eof_pattern, <<?EOF, _:4/binary>>).
-define(local_infile_pattern, <<?LOCAL_INFILE_REQUEST, _/binary>>).

%% Macros for auth methods.
-define(authmethod_none, <<>>).
-define(authmethod_mysql_native_password, <<"mysql_native_password">>).
-define(authmethod_sha256_password, <<"sha256_password">>).
-define(authmethod_caching_sha2_password, <<"caching_sha2_password">>).

%% @doc Performs a handshake using the supplied socket and socket module for
%% communication. Returns an ok or an error record. Raises errors when various
%% unimplemented features are requested.
-spec handshake(Host :: inet:socket_address() | inet:hostname(),
                Username :: iodata(), Password :: iodata(),
                Database :: iodata() | undefined,
                SockModule :: module(), SSLOpts :: list() | undefined,
                Socket :: term(),
                SetFoundRows :: boolean()) ->
    {ok, #handshake{}, SockModule :: module(), Socket :: term()} |
    #error{}.

handshake(Host, Username, Password, Database, SockModule0, SSLOpts, Socket0,
          SetFoundRows) ->
    SeqNum0 = 0,
    {ok, HandshakePacket, SeqNum1} = recv_packet(SockModule0, Socket0, SeqNum0),
    case parse_handshake(HandshakePacket) of
        #handshake{} = Handshake ->
            {ok, SockModule, Socket, SeqNum2} =
                maybe_do_ssl_upgrade(Host, SockModule0, Socket0, SeqNum1, Handshake,
                                     SSLOpts, Database, SetFoundRows),
            Response = build_handshake_response(Handshake, Username, Password,
                                                Database, SetFoundRows),
            {ok, SeqNum3} = send_packet(SockModule, Socket, Response, SeqNum2),
            handshake_finish_or_switch_auth(Handshake, Password, SockModule, Socket,
                                            SeqNum3);
        #error{} = Error ->
            Error
    end.


handshake_finish_or_switch_auth(Handshake, Password, SockModule, Socket, SeqNum) ->
    #handshake{auth_plugin_name = AuthPluginName,
               auth_plugin_data = AuthPluginData,
               server_version = ServerVersion,
               status = Status} = Handshake,
    AuthResult = auth_finish_or_switch(AuthPluginName, AuthPluginData, Password,
                                       SockModule, Socket, ServerVersion, SeqNum),
    case AuthResult of
        #ok{status = OkStatus} ->
            %% check status, ignoring bit 16#4000, SERVER_SESSION_STATE_CHANGED
            %% and bit 16#0002, SERVER_STATUS_AUTOCOMMIT.
            BitMask = bnot (?SERVER_SESSION_STATE_CHANGED bor ?SERVER_STATUS_AUTOCOMMIT),
            StatusMasked = Status band BitMask,
            StatusMasked = OkStatus band BitMask,
            {ok, Handshake, SockModule, Socket};
        Error ->
            Error
    end.

%% Finish the authentication, or switch to another auth method.
%%
%% An OK Packet signals authentication success.
%%
%% An Error Packet signals authentication failure.
%%
%% If the authentication process requires more data to be exchanged between
%% the server and client, this is done via More Data Packets. The formats and
%% meanings of the payloads in such packets depend on the auth method.
%% 
%% An Auth Method Switch Packet signals a request for transition to another
%% auth method. The packet contains the name of the auth method to switch to,
%% and new auth plugin data.
auth_finish_or_switch(AuthPluginName, AuthPluginData, Password,
                      SockModule, Socket, ServerVersion, SeqNum0) ->
    {ok, ConfirmPacket, SeqNum1} = recv_packet(SockModule, Socket, SeqNum0),
    case parse_handshake_confirm(ConfirmPacket) of
        #ok{} = Ok ->
            %% Authentication success.
            Ok;
        #auth_method_switch{auth_plugin_name = SwitchAuthPluginName,
                            auth_plugin_data = SwitchAuthPluginData} ->
            %% Server wants to transition to a different auth method.
            %% Send hash of password, calculated according to the requested auth method.
            %% (NOTE: Sending the password hash as a response to an auth method switch
            %%        is the answer for both mysql_native_password and caching_sha2_password
            %%        methods. It may be different for future other auth methods.)
            Hash = hash_password(SwitchAuthPluginName, Password, SwitchAuthPluginData),
            {ok, SeqNum2} = send_packet(SockModule, Socket, Hash, SeqNum1),
            auth_finish_or_switch(SwitchAuthPluginName, SwitchAuthPluginData, Password,
                                  SockModule, Socket, ServerVersion, SeqNum2);
        fast_auth_completed ->
            %% Server signals success by fast authentication (probably specific to
            %% the caching_sha2_password method). This will be followed by an OK Packet.
            auth_finish_or_switch(AuthPluginName, AuthPluginData, Password, SockModule,
                                  Socket, ServerVersion, SeqNum1);
        full_auth_requested when SockModule =:= ssl ->
            %% Server wants full authentication (probably specific to the
            %% caching_sha2_password method), and we are on a secure channel since
            %% our connection is through SSL. We have to reply with the null-terminated
            %% clear text password.
            Password1 = case is_binary(Password) of
                true -> Password;
                false -> iolist_to_binary(Password)
            end,
            {ok, SeqNum2} = send_packet(SockModule, Socket, <<Password1/binary, 0>>, SeqNum1),
            auth_finish_or_switch(AuthPluginName, AuthPluginData, Password, SockModule,
                                  Socket, ServerVersion, SeqNum2);
        full_auth_requested ->
            %% Server wants full authentication (probably specific to the
            %% caching_sha2_password method), and we are not on a secure channel.
            %% Since we are not implementing the client-side caching of the server's
            %% public key, we must ask for it by sending a single byte "2".
            {ok, SeqNum2} = send_packet(SockModule, Socket, <<2:8>>, SeqNum1),
            auth_finish_or_switch(AuthPluginName, AuthPluginData, Password, SockModule,
                                  Socket, ServerVersion, SeqNum2);
        {public_key, PubKey} ->
            %% Serveri has sent its public key (certainly specific to the caching_sha2_password
            %% method). We encrypt the password with the public key we received and send
            %% it back to the server.
            EncryptedPassword = encrypt_password(Password, AuthPluginData, PubKey,
                                                 ServerVersion),
            {ok, SeqNum2} = send_packet(SockModule, Socket, EncryptedPassword, SeqNum1),
            auth_finish_or_switch(AuthPluginName, AuthPluginData, Password, SockModule,
                                  Socket, ServerVersion, SeqNum2);
        Error ->
            %% Authentication failure.
            Error
    end.

-spec quit(module(), term()) -> ok.
quit(SockModule, Socket) ->
    {ok, SeqNum1} = send_packet(SockModule, Socket, <<?COM_QUIT>>, 0),
    case recv_packet(SockModule, Socket, SeqNum1) of
        {error, closed} -> ok;            %% MySQL 5.5.40 and more
        {ok, ?ok_pattern, _SeqNum2} -> ok %% Some older MySQL versions?
    end.

-spec ping(module(), term()) -> #ok{}.
ping(SockModule, Socket) ->
    {ok, SeqNum1} = send_packet(SockModule, Socket, <<?COM_PING>>, 0),
    {ok, OkPacket, _SeqNum2} = recv_packet(SockModule, Socket, SeqNum1),
    parse_ok_packet(OkPacket).

-spec query(Query :: iodata(), module(), term(), [binary()], query_filtermap(),
            timeout()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
query(Query, SockModule, Socket, AllowedPaths, FilterMap, Timeout) ->
    Req = <<?COM_QUERY, (iolist_to_binary(Query))/binary>>,
    SeqNum0 = 0,
    {ok, _SeqNum1} = send_packet(SockModule, Socket, Req, SeqNum0),
    fetch_query_response(SockModule, Socket, AllowedPaths, FilterMap, Timeout).

%% @doc This is used by query/4. If query/4 returns {error, timeout}, this
%% function can be called to retry to fetch the results of the query.
fetch_query_response(SockModule, Socket, AllowedPaths, FilterMap, Timeout) ->
    fetch_response(SockModule, Socket, Timeout, text, AllowedPaths, FilterMap, []).

%% @doc Prepares a statement.
-spec prepare(iodata(), module(), term()) -> #error{} | #prepared{}.
prepare(Query, SockModule, Socket) ->
    Req = <<?COM_STMT_PREPARE, (iolist_to_binary(Query))/binary>>,
    {ok, SeqNum1} = send_packet(SockModule, Socket, Req, 0),
    {ok, Resp, SeqNum2} = recv_packet(SockModule, Socket, SeqNum1),
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
                fetch_column_definitions_if_any(NumParams, SockModule, Socket,
                                                SeqNum2),
            %% Column Definition Block. We get column definitions in execute
            %% too, so we don't need them here. We *could* store them to be able
            %% to provide the user with some info about a prepared statement.
            {_ColDefs, _SeqNum4} =
                fetch_column_definitions_if_any(NumColumns, SockModule, Socket,
                                                SeqNum3),
            #prepared{statement_id = StmtId,
                      orig_query = Query,
                      param_count = NumParams,
                      warning_count = WarningCount}
    end.

%% @doc Deallocates a prepared statement.
-spec unprepare(#prepared{}, module(), term()) -> ok.
unprepare(#prepared{statement_id = Id}, SockModule, Socket) ->
    {ok, _SeqNum} = send_packet(SockModule, Socket,
                                <<?COM_STMT_CLOSE, Id:32/little>>, 0),
    ok.

%% @doc Executes a prepared statement.
-spec execute(#prepared{}, [term()], module(), term(), [binary()],
              query_filtermap(), timeout()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
execute(#prepared{statement_id = Id, param_count = ParamCount}, ParamValues,
        SockModule, Socket, AllowedPaths, FilterMap, Timeout)
  when ParamCount == length(ParamValues) ->
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
    {ok, _SeqNum1} = send_packet(SockModule, Socket, Req, 0),
    fetch_execute_response(SockModule, Socket, AllowedPaths, FilterMap, Timeout).

%% @doc This is used by execute/5. If execute/5 returns {error, timeout}, this
%% function can be called to retry to fetch the results of the query.
fetch_execute_response(SockModule, Socket, AllowedPaths, FilterMap, Timeout) ->
    fetch_response(SockModule, Socket, Timeout, binary, AllowedPaths, FilterMap, []).

%% @doc Changes the user of the connection.
-spec change_user(module(), term(), iodata(), iodata(), binary(), binary(),
                  undefined | iodata(), [integer()]) -> #ok{} | #error{}.
change_user(SockModule, Socket, Username, Password, AuthPluginName, AuthPluginData,
            Database, ServerVersion) ->
    DbBin = case Database of
        undefined -> <<>>;
        _ -> iolist_to_binary(Database)
    end,
    Hash = hash_password(AuthPluginName, Password, AuthPluginData),
    Req0 = <<?COM_CHANGE_USER, (iolist_to_binary(Username))/binary, 0,
            (lenenc_str_encode(Hash))/binary,
            DbBin/binary, 0, (character_set(ServerVersion)):16/little>>,
    Req1 = case AuthPluginName of
        <<>> ->
            Req0;
        _ ->
            <<Req0/binary, AuthPluginName/binary, 0>>
    end,
    {ok, SeqNum1} = send_packet(SockModule, Socket, Req1, 0),
    auth_finish_or_switch(AuthPluginName, AuthPluginData, Password,
                          SockModule, Socket, ServerVersion, SeqNum1).

-spec reset_connnection(module(), term()) -> #ok{}|#error{}.
reset_connnection(SockModule, Socket) ->
    {ok, SeqNum1} = send_packet(SockModule, Socket, <<?COM_RESET_CONNECTION>>, 0),
    {ok, Packet, _SeqNum2} = recv_packet(SockModule, Socket, SeqNum1),
    case Packet of
        ?ok_pattern ->
            parse_ok_packet(Packet);
        ?error_pattern ->
            parse_error_packet(Packet)
    end.

%% --- internal ---

%% @doc Parses a handshake. This is the first thing that comes from the server
%% when connecting. If an unsupported version or variant of the protocol is used
%% an error is raised.
-spec parse_handshake(binary()) -> #handshake{} | #error{}.
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
parse_handshake(<<?ERROR, ErrNo:16/little, Msg/binary>>) ->
    %% 'Too many connections' in MariaDB 10.1.21
    %% (Error packet in pre-4.1 protocol)
    #error{code = ErrNo, msg = Msg};
parse_handshake(<<Protocol:8, _/binary>>) when Protocol /= 10 ->
    error(unknown_protocol).

%% @doc Converts a version on the form `<<"5.6.21">' to a list `[5, 6, 21]'.
-spec server_version_to_list(binary()) -> [integer()].
server_version_to_list(ServerVersion) ->
    %% This must work with e.g. "5.5.40-0ubuntu0.12.04.1-log" and "5.5.33a".
    {match, Parts} = re:run(ServerVersion, <<"^(\\d+)\\.(\\d+)\\.(\\d+)">>,
                            [{capture, all_but_first, binary}]),
    lists:map(fun binary_to_integer/1, Parts).

-spec maybe_do_ssl_upgrade(Host :: inet:socket_address() | inet:hostname(),
                           SockModule0 :: module(),
                           Socket0 :: term(),
                           SeqNum1 :: non_neg_integer(),
                           Handshake :: #handshake{},
                           SSLOpts :: undefined | list(),
                           Database :: iodata() | undefined,
                           SetFoundRows :: boolean()) ->
    {ok, SockModule :: module(), Socket :: term(),
     SeqNum2 :: non_neg_integer()}.
maybe_do_ssl_upgrade(_Host, SockModule0, Socket0, SeqNum1, _Handshake,
                     undefined, _Database, _SetFoundRows) ->
    {ok, SockModule0, Socket0, SeqNum1};
maybe_do_ssl_upgrade(Host, gen_tcp, Socket0, SeqNum1, Handshake, SSLOpts,
                     Database, SetFoundRows) ->
    Response = build_handshake_response(Handshake, Database, SetFoundRows),
    {ok, SeqNum2} = send_packet(gen_tcp, Socket0, Response, SeqNum1),
    case ssl_connect(Host, Socket0, SSLOpts, 5000) of
        {ok, SSLSocket} ->
            {ok, ssl, SSLSocket, SeqNum2};
        {error, Reason} ->
            exit({failed_to_upgrade_socket, Reason})
    end.

ssl_connect(Host, Port, ConfigSSLOpts, Timeout) ->
    DefaultSSLOpts0 = [{versions, [tlsv1]}, {verify, verify_peer}],
    DefaultSSLOpts1 = case is_list(Host) andalso inet:parse_address(Host) of
        false -> DefaultSSLOpts0;
        {ok, _} -> DefaultSSLOpts0;
        {error, einval} -> [{server_name_indication, Host} | DefaultSSLOpts0]
    end,
    MandatorySSLOpts = [{active, false}],
    MergedSSLOpts = merge_ssl_options(DefaultSSLOpts1, MandatorySSLOpts, ConfigSSLOpts),
    ssl:connect(Port, MergedSSLOpts, Timeout).

-spec merge_ssl_options(list(), list(), list()) -> list().
merge_ssl_options(DefaultSSLOpts, MandatorySSLOpts, ConfigSSLOpts) ->
    SSLOpts1 =
    lists:foldl(fun({Key, _} = Opt, OptsAcc) ->
                        lists:keystore(Key, 1, OptsAcc, Opt)
                end, DefaultSSLOpts, ConfigSSLOpts),
    lists:foldl(fun({Key, _} = Opt, OptsAcc) ->
                        lists:keystore(Key, 1, OptsAcc, Opt)
                end, SSLOpts1, MandatorySSLOpts).

%% @doc This function is used when upgrading to encrypted socket. In other,
%% cases, build_handshake_response/5 is used.
-spec build_handshake_response(#handshake{}, iodata() | undefined, boolean()) ->
    binary().
build_handshake_response(Handshake, Database, SetFoundRows) ->
    CapabilityFlags = basic_capabilities(Database /= undefined, SetFoundRows),
    verify_server_capabilities(Handshake, CapabilityFlags),
    ClientCapabilities = add_client_capabilities(CapabilityFlags),
    ClientSSLCapabilities = ClientCapabilities bor ?CLIENT_SSL,
    CharacterSet = character_set(Handshake#handshake.server_version),
    <<ClientSSLCapabilities:32/little,
      ?MAX_BYTES_PER_PACKET:32/little,
      CharacterSet:8,
      0:23/unit:8>>.

%% @doc The response sent by the client to the server after receiving the
%% initial handshake from the server
-spec build_handshake_response(#handshake{}, iodata(), iodata(),
                               iodata() | undefined, boolean()) ->
    binary().
build_handshake_response(Handshake, Username, Password, Database,
                         SetFoundRows) ->
    CapabilityFlags = basic_capabilities(Database /= undefined, SetFoundRows),
    verify_server_capabilities(Handshake, CapabilityFlags),
    %% Add some extra capability flags only for signalling to the server what
    %% the client wants to do. The server doesn't say it handles them although
    %% it does. (http://bugs.mysql.com/bug.php?id=42268)
    ClientCapabilityFlags = add_client_capabilities(CapabilityFlags),
    AuthPluginName = Handshake#handshake.auth_plugin_name,
    AuthPluginData = Handshake#handshake.auth_plugin_data,
    Hash = hash_password(AuthPluginName, Password, AuthPluginData),
    HashLength = size(Hash),
    CharacterSet = character_set(Handshake#handshake.server_version),
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
      DbBin/binary,
      AuthPluginName/binary,
      0 %% NUL-terminator for the auth_plugin_name
      >>.

-spec verify_server_capabilities(Handshake :: #handshake{},
                                 CapabilityFlags :: integer()) ->
    true | no_return().
verify_server_capabilities(Handshake, CapabilityFlags) ->
    %% We require these capabilities. Make sure the server handles them.
    Handshake#handshake.capabilities band CapabilityFlags == CapabilityFlags
        orelse error(old_server_version).

-spec basic_capabilities(ConnectWithDB :: boolean(),
                         SetFoundRows :: boolean()) -> integer().
basic_capabilities(ConnectWithDB, SetFoundRows) ->
    CapabilityFlags0 = ?CLIENT_PROTOCOL_41 bor
                       ?CLIENT_TRANSACTIONS bor
                       ?CLIENT_SECURE_CONNECTION,
    CapabilityFlags1 = case ConnectWithDB of
                           true -> CapabilityFlags0 bor ?CLIENT_CONNECT_WITH_DB;
                           _ -> CapabilityFlags0
                       end,
    case SetFoundRows of
        true -> CapabilityFlags1 bor ?CLIENT_FOUND_ROWS;
        _    -> CapabilityFlags1
    end.

-spec add_client_capabilities(Caps :: integer()) -> integer().
add_client_capabilities(Caps) ->
    Caps bor
    ?CLIENT_MULTI_STATEMENTS bor
    ?CLIENT_MULTI_RESULTS bor
    ?CLIENT_PS_MULTI_RESULTS bor
    ?CLIENT_PLUGIN_AUTH bor
    ?CLIENT_LONG_PASSWORD bor
    ?CLIENT_LOCAL_FILES.

-spec character_set([integer()]) -> integer().
character_set(ServerVersion) when ServerVersion >= [5, 5, 3] ->
    %% https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-3.html
    ?UTF8MB4;

character_set(_ServerVersion) ->
    ?UTF8MB3.

%% @doc Handles the second packet from the server, when we have replied to the
%% initial handshake. Returns an error if the server returns an error. Raises
%% an error if unimplemented features are required.
-spec parse_handshake_confirm(binary()) ->
    #ok{} | #auth_method_switch{} | #error{} | auth_more_data().
parse_handshake_confirm(Packet = ?ok_pattern) ->
    %% Connection complete.
    parse_ok_packet(Packet);
parse_handshake_confirm(Packet = ?error_pattern) ->
    %% Access denied, insufficient client capabilities, etc.
    parse_error_packet(Packet);
parse_handshake_confirm(<<?EOF>>) ->
    %% "Old Authentication Method Switch Request Packet consisting of a
    %% single 0xfe byte. It is sent by server to request client to
    %% switch to Old Password Authentication if CLIENT_PLUGIN_AUTH
    %% capability is not supported (by either the client or the server)"
    error(old_auth);
parse_handshake_confirm(<<?EOF, AuthMethodSwitch/binary>>) ->
    %% "Authentication Method Switch Request Packet. If both server and
    %% client support CLIENT_PLUGIN_AUTH capability, server can send
    %% this packet to ask client to use another authentication method."
    parse_auth_method_switch(AuthMethodSwitch);
parse_handshake_confirm(<<?MORE_DATA, MoreData/binary>>) ->
    %% More Data Packet consisting of a 0x01 byte and a payload. This
    %% kind of packet may be used in the authentication process to
    %% provide more data to the client. It is usually followed by
    %% either an OK Packet, an Error Packet, or another More Data
    %% packet.
    parse_auth_more_data(MoreData).

%% -- both text and binary protocol --

%% @doc Fetches one or more results and and parses the result set(s) using
%% either the text format (for plain queries) or the binary format (for
%% prepared statements).
-spec fetch_response(module(), term(), timeout(), text | binary, [binary()],
                     query_filtermap(), list()) ->
    {ok, [#ok{} | #resultset{} | #error{}]} | {error, timeout}.
fetch_response(SockModule, Socket, Timeout, Proto, AllowedPaths, FilterMap, Acc) ->
    case recv_packet(SockModule, Socket, Timeout, any) of
        {ok, ?local_infile_pattern = Packet, SeqNum2} ->
            Filename = parse_local_infile_packet(Packet),
            Acc1 = case send_file(SockModule, Socket, Filename, AllowedPaths, SeqNum2) of
                {ok, _SeqNum3} ->
                    Acc;
                {{error, not_allowed}, _SeqNum3} ->
                    ErrorMsg = <<"The server requested a file not permitted by the client: ",
                                 Filename/binary>>,
                    [#error{code = -1, msg = ErrorMsg}|Acc];
                {{error, FileError}, _SeqNum3} ->
                    FileErrorMsg = list_to_binary(file:format_error(FileError)),
                    ErrorMsg = <<"The server requested a file which could not be opened "
                                 "by the client: ", Filename/binary,
                                 " (", FileErrorMsg/binary, ")">>,
                    [#error{code = -2, msg = ErrorMsg}|Acc]
            end,
            fetch_response(SockModule, Socket, Timeout, Proto, AllowedPaths,
                           FilterMap, Acc1);
        {ok, Packet, SeqNum2} ->
            Result = case Packet of
                ?ok_pattern ->
                    parse_ok_packet(Packet);
                ?error_pattern ->
                    parse_error_packet(Packet);
                ResultPacket ->
                    %% The first packet in a resultset is only the column count.
                    {ColCount, <<>>} = lenenc_int(ResultPacket),
                    fetch_resultset(SockModule, Socket, ColCount, Proto,
                                    FilterMap, SeqNum2)
            end,
            Acc1 = [Result | Acc],
            case more_results_exists(Result) of
                true ->
                    fetch_response(SockModule, Socket, Timeout, Proto,
                                   AllowedPaths, FilterMap, Acc1);
                false ->
                    {ok, lists:reverse(Acc1)}
            end;
        {error, timeout} ->
            {error, timeout}
    end.

%% @doc Fetches a result set.
-spec fetch_resultset(module(), term(), integer(), text | binary,
                      query_filtermap(), integer()) ->
    #resultset{} | #error{}.
fetch_resultset(SockModule, Socket, FieldCount, Proto, FilterMap, SeqNum0) ->
    {ok, ColDefs0, SeqNum1} = fetch_column_definitions(SockModule, Socket,
                                                       SeqNum0, FieldCount, []),
    {ok, DelimPacket, SeqNum2} = recv_packet(SockModule, Socket, SeqNum1),
    #eof{} = parse_eof_packet(DelimPacket),
    ColDefs1 = lists:map(fun parse_column_definition/1, ColDefs0),
    case fetch_resultset_rows(SockModule, Socket, FieldCount, ColDefs1, Proto,
                              FilterMap, SeqNum2, []) of
        {ok, Rows, _SeqNum3, #eof{status = S, warning_count = W}} ->
            #resultset{cols = ColDefs1, rows = Rows, status = S,
                       warning_count = W};
        #error{} = E ->
            E
    end.

%% @doc Fetches the rows for a result set and decodes them using either the text
%% format (for plain queries) or binary format (for prepared statements).
-spec fetch_resultset_rows(module(), term(), integer(), [#col{}], text | binary,
                           query_filtermap(), integer(), [[term()]]) ->
    {ok, [[term()]], integer(), #eof{}} | #error{}.
fetch_resultset_rows(SockModule, Socket, FieldCount, ColDefs, Proto,
                     FilterMap, SeqNum0, Acc) ->
    {ok, Packet, SeqNum1} = recv_packet(SockModule, Socket, SeqNum0),
    case Packet of
        ?error_pattern ->
            parse_error_packet(Packet);
        ?eof_pattern ->
            Eof = parse_eof_packet(Packet),
            {ok, lists:reverse(Acc), SeqNum1, Eof};
        RowPacket ->
            Row0=decode_row(FieldCount, ColDefs, RowPacket, Proto),
            Acc1 = case filtermap_resultset_row(FilterMap, ColDefs, Row0) of
                false ->
                    Acc;
                true ->
                    [Row0|Acc];
                {true, Row1} ->
                    [Row1|Acc]
            end,
            fetch_resultset_rows(SockModule, Socket, FieldCount, ColDefs,
                                 Proto, FilterMap, SeqNum1, Acc1)
    end.

-spec filtermap_resultset_row(query_filtermap(), [#col{}], [term()]) ->
    boolean() | {true, term()}.
filtermap_resultset_row(no_filtermap_fun, _, _) ->
    true;
filtermap_resultset_row(Fun, _, Row) when is_function(Fun, 1) ->
    Fun(Row);
filtermap_resultset_row(Fun, ColDefs, Row) when is_function(Fun, 2) ->
    Fun([Col#col.name || Col <- ColDefs], Row).

more_results_exists(#ok{status = S}) ->
    S band ?SERVER_MORE_RESULTS_EXISTS /= 0;
more_results_exists(#error{}) ->
    false; %% No status bits for error
more_results_exists(#resultset{status = S}) ->
    S band ?SERVER_MORE_RESULTS_EXISTS /= 0.

%% @doc Receives NumLeft column definition packets. They are not parsed.
%% @see parse_column_definition/1
-spec fetch_column_definitions(module(), term(), SeqNum :: integer(),
                               NumLeft :: integer(), Acc :: [binary()]) ->
    {ok, ColDefPackets :: [binary()], NextSeqNum :: integer()}.
fetch_column_definitions(SockModule, Socket, SeqNum, NumLeft, Acc)
  when NumLeft > 0 ->
    {ok, Packet, SeqNum1} = recv_packet(SockModule, Socket, SeqNum),
    fetch_column_definitions(SockModule, Socket, SeqNum1, NumLeft - 1,
                             [Packet | Acc]);
fetch_column_definitions(_SockModule, _Socket, SeqNum, 0, Acc) ->
    {ok, lists:reverse(Acc), SeqNum}.

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

%% @doc Decodes a row using either the text or binary format.
-spec decode_row(integer(), [#col{}], binary(), text | binary) -> [term()].
decode_row(FieldCount, ColDefs, RowPacket, text) ->
    decode_text_row(FieldCount, ColDefs, RowPacket);
decode_row(FieldCount, ColDefs, RowPacket, binary) ->
    decode_binary_row(FieldCount, ColDefs, RowPacket).

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
       T == ?TYPE_GEOMETRY; T == ?TYPE_JSON ->
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
fetch_column_definitions_if_any(0, _SockModule, _Socket, SeqNum) ->
    {[], SeqNum};
fetch_column_definitions_if_any(N, SockModule, Socket, SeqNum) ->
    {ok, Defs, SeqNum1} = fetch_column_definitions(SockModule, Socket, SeqNum,
                                                   N, []),
    {ok, ?eof_pattern, SeqNum2} = recv_packet(SockModule, Socket, SeqNum1),
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
       T == ?TYPE_GEOMETRY; T == ?TYPE_JSON ->
    %% As of MySQL 5.6.21 we receive SET and ENUM values as STRING, i.e. we
    %% cannot convert them to atom() or sets:set(), etc.
    lenenc_str(Data);
decode_binary(#col{type = ?TYPE_LONGLONG, flags = F},
              <<Value:64/signed-little, Rest/binary>>)
  when F band ?UNSIGNED_FLAG == 0 ->
    {Value, Rest};
decode_binary(#col{type = ?TYPE_LONGLONG, flags = F},
              <<Value:64/unsigned-little, Rest/binary>>)
  when F band ?UNSIGNED_FLAG /= 0 ->
    {Value, Rest};
decode_binary(#col{type = T, flags = F},
              <<Value:32/signed-little, Rest/binary>>)
  when (T == ?TYPE_LONG orelse T == ?TYPE_INT24) andalso
       F band ?UNSIGNED_FLAG == 0 ->
    {Value, Rest};
decode_binary(#col{type = T, flags = F},
              <<Value:32/unsigned-little, Rest/binary>>)
  when (T == ?TYPE_LONG orelse T == ?TYPE_INT24) andalso
       F band ?UNSIGNED_FLAG /= 0 ->
    {Value, Rest};
decode_binary(#col{type = ?TYPE_SHORT, flags = F},
              <<Value:16/signed-little, Rest/binary>>)
  when F band ?UNSIGNED_FLAG == 0 ->
    {Value, Rest};
decode_binary(#col{type = T, flags = F},
              <<Value:16/unsigned-little, Rest/binary>>)
  when (T == ?TYPE_SHORT orelse T == ?TYPE_YEAR) andalso
       F band ?UNSIGNED_FLAG /= 0 ->
    {Value, Rest};
decode_binary(#col{type = ?TYPE_TINY, flags = F},
              <<Value:8/unsigned, Rest/binary>>)
  when F band ?UNSIGNED_FLAG /= 0 ->
    {Value, Rest};
decode_binary(#col{type = ?TYPE_TINY, flags = F},
              <<Value:8/signed, Rest/binary>>)
  when F band ?UNSIGNED_FLAG == 0 ->
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
    %%     max decimal precision = 10 ^ (-5 + flooring(yourNumber log 10))
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
    Factor = math:pow(10, flooring(6 - math:log10(abs(Value)))),
    RoundedValue = round(Value * Factor) / Factor,
    {RoundedValue, Rest};
decode_binary(#col{type = ?TYPE_BIT, length = Length}, Data) ->
    {Binary, Rest} = lenenc_str(Data),
    %% Convert to <<_:Length/bitstring>>
    {decode_bitstring(Binary, Length), Rest};
decode_binary(#col{type = ?TYPE_DATE}, Data) ->
    %% Coded in the same way as DATETIME and TIMESTAMP below, but returned in
    %% a simple triple.
    case lenenc_int(Data) of
        {0, Rest} -> {{0, 0, 0}, Rest};
        {4, <<Y:16/little, M, D, Rest/binary>>} -> {{Y, M, D}, Rest}
    end;
decode_binary(#col{type = T}, Data)
  when T == ?TYPE_DATETIME; T == ?TYPE_TIMESTAMP ->
    %% length (1) -- number of bytes following (valid values: 0, 4, 7, 11)
    case lenenc_int(Data) of
        {0, Rest} ->
            {{{0, 0, 0}, {0, 0, 0}}, Rest};
        {4, <<Y:16/little, M, D, Rest/binary>>} ->
            {{{Y, M, D}, {0, 0, 0}}, Rest};
        {7, <<Y:16/little, M, D, H, Mi, S, Rest/binary>>} ->
            {{{Y, M, D}, {H, Mi, S}}, Rest};
        {11, <<Y:16/little, M, D, H, Mi, S, Micro:32/little, Rest/binary>>} ->
            {{{Y, M, D}, {H, Mi, S + 0.000001 * Micro}}, Rest}
    end;
decode_binary(#col{type = ?TYPE_TIME}, Data) ->
    %% length (1) -- number of bytes following (valid values: 0, 8, 12)
    %% is_negative (1) -- (1 if minus, 0 for plus)
    %% days (4) -- days
    %% hours (1) -- hours
    %% minutes (1) -- minutes
    %% seconds (1) -- seconds
    %% micro_seconds (4) -- micro-seconds
    case lenenc_int(Data) of
        {0, Rest} ->
            {{0, {0, 0, 0}}, Rest};
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
flooring(Value) ->
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
encode_param({decimal, Value}) ->
    Bin = if is_binary(Value) -> Value;
             is_list(Value) -> list_to_binary(Value);
             is_integer(Value) -> integer_to_binary(Value);
             is_float(Value) -> list_to_binary(io_lib:format("~w", [Value]))
          end,
    EncLength = lenenc_int_encode(byte_size(Bin)),
    {<<?TYPE_DECIMAL, 0>>, <<EncLength/binary, Bin/binary>>};
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

%% @doc Checks if the given Parameters can be encoded for use in the
%% binary protocol. Returns `true' if all of the parameters can be
%% encoded, `false' if any of them cannot be encoded.
-spec valid_params([term()]) -> boolean().
valid_params(Values) when is_list(Values) ->
    lists:all(fun is_valid_param/1, Values).

%% @doc Checks if the given parameter can be encoded for use in the
%% binary protocol.
-spec is_valid_param(term()) -> boolean().
is_valid_param(null) ->
    true;
is_valid_param(Value) when is_list(Value) ->
    try
        unicode:characters_to_binary(Value)
    of
        Value1 when is_binary(Value1) ->
            true;
        _ErrorOrIncomplete ->
            false
    catch
        error:badarg ->
            false
    end;
is_valid_param(Value) when is_number(Value) ->
    true;
is_valid_param({decimal, Value}) when is_binary(Value); is_list(Value);
                                      is_float(Value); is_integer(Value) ->
    true;
is_valid_param(Value) when is_bitstring(Value) ->
    true;
is_valid_param({Y, M, D}) ->
    is_integer(Y) andalso is_integer(M) andalso is_integer(D);
is_valid_param({{Y, M, D}, {H, Mi, S}}) ->
    is_integer(Y) andalso is_integer(M) andalso is_integer(D) andalso
    is_integer(H) andalso is_integer(Mi) andalso is_number(S);
is_valid_param({D, {H, M, S}}) ->
    is_integer(D) andalso
    is_integer(H) andalso is_integer(M) andalso is_number(S);
is_valid_param(_) ->
    false.

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

%% @doc Wraps Data in packet headers, sends it by calling SockModule:send/2 with
%% Socket and returns {ok, SeqNum1} where SeqNum1 is the next sequence number.
-spec send_packet(module(), term(), Data :: binary(), SeqNum :: integer()) ->
    {ok, NextSeqNum :: integer()}.
send_packet(SockModule, Socket, Data, SeqNum) ->
    {WithHeaders, SeqNum1} = add_packet_headers(Data, SeqNum),
    ok = SockModule:send(Socket, WithHeaders),
    {ok, SeqNum1}.

%% @see recv_packet/4
recv_packet(SockModule, Socket, SeqNum) ->
    recv_packet(SockModule, Socket, infinity, SeqNum).

%% @doc Receives data by calling SockModule:recv/2 and removes the packet
%% headers. Returns the packet contents and the next packet sequence number.
-spec recv_packet(module(), term(), timeout(), integer() | any) ->
    {ok, Data :: binary(), NextSeqNum :: integer()} | {error, term()}.
recv_packet(SockModule, Socket, Timeout, SeqNum) ->
    recv_packet(SockModule, Socket, Timeout, SeqNum, <<>>).

%% @doc Accumulating helper for recv_packet/4
-spec recv_packet(module(), term(), timeout(), integer() | any, binary()) ->
    {ok, Data :: binary(), NextSeqNum :: integer()} | {error, term()}.
recv_packet(SockModule, Socket, Timeout, ExpectSeqNum, Acc) ->
    case SockModule:recv(Socket, 4, Timeout) of
        {ok, Header} ->
            {Size, SeqNum, More} = parse_packet_header(Header),
            true = SeqNum == ExpectSeqNum orelse ExpectSeqNum == any,
            {ok, Body} = SockModule:recv(Socket, Size),
            Acc1 = <<Acc/binary, Body/binary>>,
            NextSeqNum = (SeqNum + 1) band 16#ff,
            case More of
                false -> {ok, Acc1, NextSeqNum};
                true  -> recv_packet(SockModule, Socket, Timeout, NextSeqNum,
                                     Acc1)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

-spec send_file(module(), term(), Filename :: binary(), AllowedPaths :: [binary()],
                SeqNum :: integer()) ->
    {ok | {error, Reason}, NextSeqNum :: integer()}
    when Reason :: not_allowed
	         | file:posix()
		 | badarg
		 | system_limit.
send_file(SockModule, Socket, Filename, AllowedPaths, SeqNum0) ->
    {Result, SeqNum1} = case allowed_path(Filename, AllowedPaths) andalso
                             file:open(Filename, [read, raw, binary]) of
        false ->
            {{error, not_allowed}, SeqNum0};
        {ok, Handle} ->
            {ok, SeqNum2} = send_file_chunk(SockModule, Socket, Handle, SeqNum0),
            ok = file:close(Handle),
            {ok, SeqNum2};
        {error, _Reason} = E ->
            {E, SeqNum0}
    end,
    {ok, SeqNum3} = send_packet(SockModule, Socket, <<>>, SeqNum1),
    {Result, SeqNum3}.

-spec allowed_path(binary(), [binary()]) -> boolean().
allowed_path(Path, AllowedPaths) ->
    valid_path(Path) andalso
    binary:last(Path) =/= $/ andalso
    lists:any(
        fun
            (AllowedPath) when Path =:= AllowedPath ->
                true;
            (AllowedPath) ->
                Size = byte_size(AllowedPath),
                HasSlash = binary:last(AllowedPath) =:= $/,
                case Path of
                    <<AllowedPath:Size/binary, _/binary>> when HasSlash -> true;
                    <<AllowedPath:Size/binary, $/, _/binary>> -> true;
                    _ -> false
                end
        end,
        AllowedPaths
    ).

%% @doc Checks if the argument is a valid path.
%%
%% Returns `true' if the argument is an absolute path that does not contain
%% any relative components like `..' or `.', otherwise `false'.
-spec valid_path(term()) -> boolean().
valid_path(Path) when is_binary(Path), byte_size(Path) > 0 ->
    case filename:pathtype(Path) of
        absolute ->
            valid_abspath(Path);
        volumerelative ->
            case Path of
                <<$/, _/binary>> ->
                    false;
                _ ->
                    valid_abspath(Path)
            end;
        relative ->
            false
    end;
valid_path(_Path) ->
    false.

-spec valid_abspath(<<_:8, _:_*8>>) -> boolean().
valid_abspath(Path) ->
    lists:all(
        fun
            (<<".">>) -> false;
            (<<"..">>) -> false;
            (_) -> true
        end,
        filename:split(Path)
    ).

-spec send_file_chunk(module(), term(), Handle :: file:io_device(), SeqNum :: integer()) ->
    {ok, NextSeqNum :: integer()}.
send_file_chunk(SockModule, Socket, Handle, SeqNum0) ->
    case file:read(Handle, 16#ffffff) of
        eof ->
            {ok, SeqNum0};
        {ok, <<>>} ->
            send_file_chunk(SockModule, Socket, Handle, SeqNum0);
        {ok, Data} ->
            {ok, SeqNum1} = send_packet(SockModule, Socket, Data, SeqNum0),
            send_file_chunk(SockModule, Socket, Handle, SeqNum1)
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
%% resulting list is ready to be sent to the socket. The result is built as a
%% list to avoid copying large binaries.
-spec add_packet_headers(Data :: binary(), SeqNum :: integer()) ->
    {PacketsWithHeaders :: iodata(), NextSeqNum :: integer()}.
add_packet_headers(<<Payload:16#ffffff/binary, Rest/binary>>, SeqNum) ->
    SeqNum1 = (SeqNum + 1) band 16#ff,
    {Packets, NextSeqNum} = add_packet_headers(Rest, SeqNum1),
    Header = <<16#ffffff:24/little, SeqNum:8>>,
    {[Header, Payload | Packets], NextSeqNum};
add_packet_headers(Bin, SeqNum) when byte_size(Bin) < 16#ffffff ->
    NextSeqNum = (SeqNum + 1) band 16#ff,
    Header = <<(byte_size(Bin)):24/little, SeqNum:8>>,
    {[Header, Bin], NextSeqNum}.

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

parse_local_infile_packet(<<?LOCAL_INFILE_REQUEST:8, FileName/binary>>) ->
    FileName.

-spec parse_auth_method_switch(binary()) -> #auth_method_switch{}.
parse_auth_method_switch(AMSData) ->
    {AuthPluginName, AuthPluginData} = get_null_terminated_binary(AMSData),
    #auth_method_switch{
       auth_plugin_name = AuthPluginName,
       auth_plugin_data = AuthPluginData
      }.

-spec parse_auth_more_data(binary()) -> auth_more_data().
parse_auth_more_data(<<3>>) ->
    %% With caching_sha2_password authentication, a single 0x03
    %% byte signals Fast Auth Success.
    fast_auth_completed;
parse_auth_more_data(<<4>>) ->
    %% With caching_sha2_password authentication, a single 0x04
    %% byte signals a Full Auth Request.
    full_auth_requested;
parse_auth_more_data(Data) ->
    %% With caching_sha2_password authentication, anything
    %% other than the above should be the public key of the
    %% server.
    PubKey = case public_key:pem_decode(Data) of
        [PemEntry = #'SubjectPublicKeyInfo'{}] ->
            public_key:pem_entry_decode(PemEntry);
        [PemEntry = #'RSAPublicKey'{}] ->
            PemEntry
    end,
    {public_key, PubKey}.

-spec get_null_terminated_binary(binary()) -> {Binary :: binary(),
                                               Rest :: binary()}.
get_null_terminated_binary(In) ->
    get_null_terminated_binary(In, <<>>).

get_null_terminated_binary(<<0, Rest/binary>>, Acc) ->
    {Acc, Rest};
get_null_terminated_binary(<<Ch, Rest/binary>>, Acc) ->
    get_null_terminated_binary(Rest, <<Acc/binary, Ch>>).

-spec hash_password(AuthMethod, Password, Salt) -> Hash
  when AuthMethod :: binary(),
       Password :: iodata(),
       Salt :: binary(),
       Hash :: binary().
hash_password(AuthMethod, Password, Salt) when not is_binary(Password) ->
    hash_password(AuthMethod, iolist_to_binary(Password), Salt);
hash_password(?authmethod_none, Password, Salt) ->
    hash_password(?authmethod_mysql_native_password, Password, Salt);
hash_password(?authmethod_mysql_native_password, <<>>, _Salt) ->
    <<>>;
hash_password(?authmethod_mysql_native_password, Password, Salt) ->
    %% From the "MySQL Internals" manual:
    %% SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat>
    %%                            SHA1( SHA1( password ) ) )
    Salt1 = trim_salt(Salt),
    <<Hash1Num:160>> = Hash1 = crypto:hash(sha, Password),
    Hash2 = crypto:hash(sha, Hash1),
    <<Hash3Num:160>> = crypto:hash(sha, <<Salt1/binary, Hash2/binary>>),
    <<(Hash1Num bxor Hash3Num):160>>;
hash_password(?authmethod_caching_sha2_password, <<>>, _Salt) ->
    <<>>;
hash_password(?authmethod_caching_sha2_password, Password, Salt) ->
    %% From https://dev.mysql.com/doc/dev/mysql-server/latest/page_caching_sha2_authentication_exchanges.html
    %% (transcribed):
    %% SHA256( password ) XOR SHA256( SHA256( SHA256( password ) ) <concat>
    %%                                        "20-bytes random data from server" )
    Salt1 = trim_salt(Salt),
    <<Hash1Num:256>> = Hash1 = crypto:hash(sha256, Password),
    Hash2 = crypto:hash(sha256, Hash1),
    <<Hash3Num:256>> = crypto:hash(sha256, <<Hash2/binary, Salt1/binary>>),
    <<(Hash1Num bxor Hash3Num):256>>;
hash_password(?authmethod_sha256_password, Password, Salt) ->
    %% sha256_password authentication is superseded by
    %% caching_sha2_password.
    hash_password(?authmethod_caching_sha2_password, Password, Salt);
hash_password(UnknownAuthMethod, _, _) ->
    error({auth_method, UnknownAuthMethod}).

encrypt_password(Password, Salt, PubKey, ServerVersion)
  when is_binary(Password) ->
    %% From http://www.dataarchitect.cloud/preparing-your-community-connector-for-mysql-8-part-2-sha256/:
    %% "The password is "obfuscated" first by employing a rotating "xor" against
    %% the seed bytes that were given to the authentication plugin upon initial
    %% handshake [the auth plugin data].
    %% [...]
    %% Buffer would then be encrypted using the RSA public key the server passed
    %% to the client.  The resulting buffer would then be passed back to the
    %% server."
    Salt1 = trim_salt(Salt),

    %% While the article does not mention it, the password must be null-terminated
    %% before obfuscation.
    Password1 = <<Password/binary, 0>>,
    Salt2 = case byte_size(Salt1)<byte_size(Password1) of
        true ->
            binary:copy(Salt1, (byte_size(Password1) div byte_size(Salt1)) + 1);
        false ->
            Salt1
    end,
    Size = bit_size(Password1),
    <<PasswordNum:Size>> = Password1,
    <<SaltNum:Size, _/bitstring>> = Salt2,
    Password2 = <<(PasswordNum bxor SaltNum):Size>>,

    %% From http://www.dataarchitect.cloud/preparing-your-community-connector-for-mysql-8-part-2-sha256/:
    %% "It's important to note that a incompatible change happened in server 8.0.5.
    %% Prior to server 8.0.5 the encryption was done using RSA_PKCS1_PADDING.
    %% With 8.0.5 it is done with RSA_PKCS1_OAEP_PADDING."
    RsaPadding = case ServerVersion < [8, 0, 5] of
        true -> rsa_pkcs1_padding;
        false -> rsa_pkcs1_oaep_padding
    end,
    %% The option rsa_pad was renamed to rsa_padding in OTP/22, but rsa_pad
    %% is being kept for backwards compatibility.
    public_key:encrypt_public(Password2, PubKey, [{rsa_pad, RsaPadding}]);
encrypt_password(Password, Salt, PubKey, ServerVersion) ->
    encrypt_password(iolist_to_binary(Password), Salt, PubKey, ServerVersion).

trim_salt(<<SaltNoNul:20/binary-unit:8, 0>>) ->
    SaltNoNul;
trim_salt(Salt = <<_:20/binary-unit:8>>) ->
    Salt.

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

%% Length-encoded-string encode. Prefixes the value with a
%% length-encoded-integer denoting its size.
-spec lenenc_str_encode(Input :: binary()) -> binary().
lenenc_str_encode(Bin) ->
    Length = byte_size(Bin),
    <<(lenenc_int_encode(Length))/binary, Bin:Length/binary>>.

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

add_packet_headers_equal_to_0xffffff_test() ->
    BigBin = binary:copy(<<1>>, 16#ffffff),
    {Data, 44} = add_packet_headers(BigBin, 42),
    ?assertEqual(<<16#ff, 16#ff, 16#ff, 42, BigBin/binary,
                   0,     0,     0,     43>>,
                 list_to_binary(Data)).

add_packet_headers_greater_than_0xffffff_test() ->
    BigBin = binary:copy(<<1>>, 16#ffffff),
    {Data, 44} = add_packet_headers(<<BigBin/binary, "foo">>, 42),
    ?assertEqual(<<16#ff, 16#ff, 16#ff, 42, BigBin/binary, 3, 0, 0, 43, "foo">>,
                 list_to_binary(Data)).

add_packet_headers_2_times_greater_than_0xffffff_test() ->
    BigBin = binary:copy(<<1>>, 16#ffffff),
    {Data, 45} = add_packet_headers(<<BigBin/binary, BigBin/binary, "foo">>, 42),
    ?assertEqual(<<16#ff, 16#ff, 16#ff, 42, BigBin/binary,
                   16#ff, 16#ff, 16#ff, 43, BigBin/binary,
                   3,     0,     0,     44, "foo">>,
                 list_to_binary(Data)).

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
                 hash_password(?authmethod_mysql_native_password,
                               <<"foo">>, <<"abcdefghijklmnopqrst">>)),
    ?assertEqual(<<>>, hash_password(?authmethod_mysql_native_password,
                                     <<>>, <<"abcdefghijklmnopqrst">>)),
    ?assertEqual(<<125,155,142,2,20,139,6,254,65,126,239,
                   146,107,77,17,8,120,55,247,33,87,16,76,
                   63,128,131,60,188,58,81,171,242>>,
                 hash_password(?authmethod_caching_sha2_password,
                               <<"foo">>, <<"abcdefghijklmnopqrst">>)),
    ?assertEqual(<<>>, hash_password(?authmethod_caching_sha2_password,
                                     <<>>, <<"abcdefghijklmnopqrst">>)).

valid_params_test() ->
    ValidParams = [
        null,
        1,
        0.5,
        <<>>, <<$x>>, <<0:1>>,

        %% valid unicode
        [], [$x], [16#E4],

        %% valid date
        {1, 2, 3},

        %% valid time
        {1, {2, 3, 4}}, {1, {2, 3, 4.5}},

        %% valid datetime
        {{1, 2, 3}, {4, 5, 6}}, {{1, 2, 3}, {4, 5, 6.5}}
    ],

    InvalidParams = [
        x,
        [x],
        {},
        self(),
        make_ref(),
        fun () -> ok end,

        %% invalid unicode
        [16#FFFFFFFF],

        %% invalid date
        {x, 1, 2}, {1, x, 2}, {1, 2, x},

        %% invalid time
        {x, {1, 2, 3}}, {1, {x, 2, 3}},
        {1, {2, x, 3}}, {1, {2, 3, x}},

        %% invalid datetime
        {{x, 1, 2}, {3, 4, 5}}, {{1, x, 2}, {3, 4, 5}},
        {{1, 2, x}, {3, 4, 5}}, {{1, 2, 3}, {x, 4, 5}},
        {{1, 2, 3}, {4, x, 5}}, {{1, 2, 3}, {4, 5, x}}
    ],

    lists:foreach(
        fun (ValidParam) ->
            ?assert(is_valid_param(ValidParam))
        end,
        ValidParams),
    ?assert(valid_params(ValidParams)),

    lists:foreach(
        fun (InvalidParam) ->
            ?assertNot(is_valid_param(InvalidParam))
        end,
        InvalidParams),
    ?assertNot(valid_params(InvalidParams)),
    ?assertNot(valid_params(ValidParams ++ InvalidParams)).

valid_path_test() ->
    ValidPaths = [
        <<"/">>,
        <<"/tmp">>,
        <<"/tmp/">>,
        <<"/tmp/foo">>
    ],
    InvalidPaths = [
        <<>>,
        <<"tmp">>,
        <<"tmp/">>,
        <<"tmp/foo">>,
        <<"../tmp">>,
        <<"/tmp/..">>,
        <<"/tmp/foo/../bar">>,
        "/tmp"
    ],
    lists:foreach(
        fun (ValidPath) ->
            ?assert(valid_path(ValidPath))
        end,
        ValidPaths
    ),
    lists:foreach(
        fun (InvalidPath) ->
            ?assertNot(valid_path(InvalidPath))
        end,
        InvalidPaths
    ).

allowed_path_test() ->
    AllowedPaths = [
        <<"/tmp/foo/file.csv">>,
        <<"/tmp/foo/bar/">>,
        <<"/tmp/foo/baz">>
    ],
    ValidPaths = [
        <<"/tmp/foo/file.csv">>,
        <<"/tmp/foo/bar/file.csv">>,
        <<"/tmp/foo/baz/file.csv">>,
        <<"/tmp/foo/baz">>
    ],
    InvalidPaths = [
        <<"/tmp/file.csv">>,
        <<"/tmp/foo/other_file.csv">>,
        <<"/tmp/foo/other_dir/file.csv">>,
        <<"/tmp/foo/../file.csv">>,
        <<"/tmp/foo/../bar/file.csv">>,
        <<"/tmp/foo/bar/">>,
        <<"/tmp/foo/barbaz">>
    ],
    lists:foreach(
        fun (ValidPath) ->
            ?assert(allowed_path(ValidPath, AllowedPaths))
        end,
        ValidPaths
    ),
    lists:foreach(
        fun (InvalidPath) ->
            ?assertNot(allowed_path(InvalidPath, AllowedPaths))
        end,
        InvalidPaths
    ).

-endif.

