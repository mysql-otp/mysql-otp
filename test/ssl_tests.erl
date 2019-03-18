%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2017 Piotr Nosek
%% Copyright (C) 2017-2018 Viktor Söderqvist
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

%% @doc This module tests to connect to a database over SSL.
-module(ssl_tests).

-include_lib("eunit/include/eunit.hrl").

-define(ssl_user,     "otptestssl").
-define(ssl_password, "otptestssl").
-define(cacertfile,   "test/ssl/ca.pem").

successful_ssl_connect_test() ->
    [ application:start(App) || App <- [crypto, asn1, public_key, ssl] ],
    common_basic_check([{ssl, [{server_name_indication, disable},
                               {cacertfile, ?cacertfile}]},
                        {user, ?ssl_user}, {password, ?ssl_password}]),
    common_conn_close(),
    ok.

common_basic_check(ExtraOpts) ->
    Options = [{name, {local, tardis}},
               {queries, ["SET @foo = 'bar'", "SELECT 1",
                          "SELECT 1; SELECT 2"]},
               {prepare, [{foo, "SELECT @foo"}]} | ExtraOpts],
    {ok, Pid} = mysql:start_link(Options),
    %% Check that queries and prepare has been done.
    ?assertEqual({ok, [<<"@foo">>], [[<<"bar">>]]},
                 mysql:execute(Pid, foo, [])),
    Pid.

common_conn_close() ->
    Pid = whereis(tardis),
    mysql:stop(Pid, 5000).
