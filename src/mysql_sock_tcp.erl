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

%% @doc This module provides TCP socket interface, i.e. is a proxy to gen_tcp and inet.
%% @private
-module(mysql_sock_tcp).

-export([connect/3, close/1, send/2, recv/2, recv/3]).
-export([setopts/2]).

connect(Host, Port, SockOpts) ->
    gen_tcp:connect(Host, Port, SockOpts).

close(Socket) ->
    gen_tcp:close(Socket).

send(Socket, Packet) ->
    gen_tcp:send(Socket, Packet).

recv(Socket, Length) ->
    gen_tcp:recv(Socket, Length).

recv(Socket, Length, Timeout) ->
    gen_tcp:recv(Socket, Length, Timeout).

setopts(Socket, SockOpts) ->
    inet:setopts(Socket, SockOpts).
