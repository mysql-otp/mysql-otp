%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
%% Copyright (C) 2016 Feng Lee
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

-module(mock_protocol).

-author("Feng Lee <feng@emqtt.io>").

-export([init/1, init/2, feed/3, close/1]).

init(Sock) ->
    init(self(), Sock).

init(ParentPid, Sock) ->
    Receiver = spawn(fun() ->
                   mysql_socket:receiver_loop(ParentPid, Sock, mysql_socket:parser())
               end),
    SendFun = fun(Data) -> mock_tcp:send(Sock, Data) end,
    {mysql_protocol, [SendFun, Receiver]}.

feed(Sock, Packet, {mysql_protocol, [_SendFun, Receiver]}) ->
    Receiver ! {tcp, Sock, Packet}.

close({mysql_protocol, [_Sock, Receiver]}) ->
    exit(Receiver, normal).

