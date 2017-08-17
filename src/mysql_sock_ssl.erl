%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2017 Piotr Nosek, Michal Slaski
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

%% @doc This module provides SSL socket interface, i.e. is a proxy to ssl module.
%% @private
-module(mysql_sock_ssl).

-export([connect/3, close/1, send/2, recv/2, recv/3]).
-export([setopts/2]).

%% --------------------------------------------------
%% API
%% --------------------------------------------------

connect(Port, ConfigSSLOpts, Timeout) ->
    DefaultSSLOpts = [{versions, [tlsv1]}, {verify, verify_peer}],
    MandatorySSLOpts = [{active, false}],
    MergedSSLOpts = merge_ssl_options(DefaultSSLOpts, MandatorySSLOpts, ConfigSSLOpts),
    ssl:connect(Port, MergedSSLOpts, Timeout).

close(Socket) ->
    ssl:close(Socket).

send(Socket, Packet) ->
    ssl:send(Socket, Packet).

recv(Socket, Length) ->
    ssl:recv(Socket, Length).

recv(Socket, Length, Timeout) ->
    ssl:recv(Socket, Length, Timeout).

setopts(Socket, SockOpts) ->
    ssl:setopts(Socket, SockOpts).

%% --------------------------------------------------
%% Internal functions
%% --------------------------------------------------

-spec merge_ssl_options(list(), list(), list()) -> list().
merge_ssl_options(DefaultSSLOpts, MandatorySSLOpts, ConfigSSLOpts) ->
    SSLOpts1 =
    lists:foldl(fun({Key, _} = Opt, OptsAcc) ->
                        lists:keystore(Key, 1, OptsAcc, Opt)
                end, DefaultSSLOpts, ConfigSSLOpts),
    lists:foldl(fun({Key, _} = Opt, OptsAcc) ->
                        lists:keystore(Key, 1, OptsAcc, Opt)
                end, SSLOpts1, MandatorySSLOpts).

