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

%% @doc MySQL Packet Builder
%%
%% This module builds MySQL packets to binary.

-module(mysql_builder).

-author("Feng Lee <feng@emqtt.io>").

-include("protocol.hrl").

-include("records.hrl").

-export([build_handshake_response/4]).

%% How much data do we want per packet?
-define(MAX_BYTES_PER_PACKET, 16#1000000).

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


