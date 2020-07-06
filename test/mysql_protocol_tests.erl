%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
%%               2017 Piotr Nosek
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

%% @doc Eunit test cases for the mysql_protocol module.
%% Most of the hexdump tests are from examples in the protocol documentation.
%%
%% TODO: Use ngrep -x -q -d lo '' 'port 3306' to dump traffic using various
%% server versions.
-module(mysql_protocol_tests).

-include_lib("eunit/include/eunit.hrl").

-include("protocol.hrl").
-include("records.hrl").

resultset_test() ->
    %% A query that returns a result set in the text protocol.
    Query = <<"SELECT @@version_comment">>,
    ExpectedReq = <<(size(Query) + 1):24/little, 0, ?COM_QUERY, Query/binary>>,
    ExpectedResponse = hexdump_to_bin(
        "01 00 00 01 01|27 00 00    02 03 64 65 66 00 00 00    .....'....def..."
        "11 40 40 76 65 72 73 69    6f 6e 5f 63 6f 6d 6d 65    .@@version_comme"
        "6e 74 00 0c 08 00 1c 00    00 00 fd 00 00 1f 00 00|   nt.............."
        "05 00 00 03 fe 00 00 02    00|1d 00 00 04 1c 4d 79    ..............My"
        "53 51 4c 20 43 6f 6d 6d    75 6e 69 74 79 20 53 65    SQL Community Se"
        "72 76 65 72 20 28 47 50    4c 29|05 00 00 05 fe 00    rver (GPL)......"
        "00 02 00                                              ..."),
    ExpectedCommunication = [{send, ExpectedReq},
                             {recv, ExpectedResponse}],
    Sock = mock_tcp:create(ExpectedCommunication),
    {ok, [ResultSet]} = mysql_protocol:query(Query, mock_tcp, Sock, [],
                                             no_filtermap_fun, infinity),
    mock_tcp:close(Sock),
    ?assertMatch(#resultset{cols = [#col{name = <<"@@version_comment">>}],
                            rows = [[<<"MySQL Community Server (GPL)">>]]},
                 ResultSet),
    ok.

resultset_error_test() ->
    %% A query that returns a response starting as a result set but then
    %% interupts itself and decides that it is an error.
    Query = <<"EXPLAIN SELECT * FROM dual;">>,
    ExpectedReq = <<(size(Query) + 1):24/little, 0, ?COM_QUERY, Query/binary>>,
    ExpectedResponse = hexdump_to_bin(
        "01 00 00 01 0a 18 00 00    02 03 64 65 66 00 00 00    ..........def..."
        "02 69 64 00 0c 3f 00 03    00 00 00 08 a1 00 00 00    .id..?.........."
        "00 21 00 00 03 03 64 65    66 00 00 00 0b 73 65 6c    .!....def....sel"
        "65 63 74 5f 74 79 70 65    00 0c 08 00 13 00 00 00    ect_type........"
        "fd 01 00 1f 00 00 1b 00    00 04 03 64 65 66 00 00    ...........def.."
        "00 05 74 61 62 6c 65 00    0c 08 00 40 00 00 00 fd    ..table....@...."
        "00 00 1f 00 00 1a 00 00    05 03 64 65 66 00 00 00    ..........def..."
        "04 74 79 70 65 00 0c 08    00 0a 00 00 00 fd 00 00    .type..........."
        "1f 00 00 23 00 00 06 03    64 65 66 00 00 00 0d 70    ...#....def....p"
        "6f 73 73 69 62 6c 65 5f    6b 65 79 73 00 0c 08 00    ossible_keys...."
        "00 10 00 00 fd 00 00 1f    00 00 19 00 00 07 03 64    ...............d"
        "65 66 00 00 00 03 6b 65    79 00 0c 08 00 40 00 00    ef....key....@.."
        "00 fd 00 00 1f 00 00 1d    00 00 08 03 64 65 66 00    ............def."
        "00 00 07 6b 65 79 5f 6c    65 6e 00 0c 08 00 00 10    ...key_len......"
        "00 00 fd 00 00 1f 00 00    19 00 00 09 03 64 65 66    .............def"
        "00 00 00 03 72 65 66 00    0c 08 00 00 04 00 00 fd    ....ref........."
        "00 00 1f 00 00 1a 00 00    0a 03 64 65 66 00 00 00    ..........def..."
        "04 72 6f 77 73 00 0c 3f    00 0a 00 00 00 08 a0 00    .rows..?........"
        "00 00 00 1b 00 00 0b 03    64 65 66 00 00 00 05 45    ........def....E"
        "78 74 72 61 00 0c 08 00    ff 00 00 00 fd 01 00 1f    xtra............"
        "00 00 05 00 00 0c fe 00    00 02 00 17 00 00 0d ff    ................"
        "48 04 23 48 59 30 30 30    4e 6f 20 74 61 62 6c 65    H.#HY000No table"
        "73 20 75 73 65 64                                     s used"),
    Sock = mock_tcp:create([{send, ExpectedReq}, {recv, ExpectedResponse}]),
    {ok, [Result]} = mysql_protocol:query(Query, mock_tcp, Sock, [],
                                          no_filtermap_fun, infinity),
    ?assertMatch(#error{}, Result),
    mock_tcp:close(Sock),
    ok.

prepare_test() ->
    %% Prepared statement. The example from "14.7.4 COM_STMT_PREPARE" in the
    %% "MySQL Internals" guide.
    Query = <<"SELECT CONCAT(?, ?) AS col1">>,
    ExpectedReq = hexdump_to_bin(
        "1c 00 00 00 16 53 45 4c    45 43 54 20 43 4f 4e 43    .....SELECT CONC"
        "41 54 28 3f 2c 20 3f 29    20 41 53 20 63 6f 6c 31    AT(?, ?) AS col1"
        ),
    ExpectedResp = hexdump_to_bin(
        "0c 00 00 01 00 01 00 00    00 01 00 02 00 00 00 00|   ................"
        "17 00 00 02 03 64 65 66    00 00 00 01 3f 00 0c 3f    .....def....?..?"
        "00 00 00 00 00 fd 80 00    00 00 00|17 00 00 03 03    ................"
        "64 65 66 00 00 00 01 3f    00 0c 3f 00 00 00 00 00    def....?..?....."
        "fd 80 00 00 00 00|05 00    00 04 fe 00 00 02 00|1a    ................"
        "00 00 05 03 64 65 66 00    00 00 04 63 6f 6c 31 00    ....def....col1."
        "0c 3f 00 00 00 00 00 fd    80 00 1f 00 00|05 00 00    .?.............."
        "06 fe 00 00 02 00                                     ......"),
    Sock = mock_tcp:create([{send, ExpectedReq}, {recv, ExpectedResp}]),
    Result = mysql_protocol:prepare(Query, mock_tcp, Sock),
    mock_tcp:close(Sock),
    ?assertMatch(#prepared{statement_id = StmtId,
                           param_count = 2,
                           warning_count = 0} when is_integer(StmtId),
                 Result),
    ok.

bad_protocol_version_test() ->
    Sock = mock_tcp:create([{recv, <<2, 0, 0, 0, 9, 0>>}]),
    SSLOpts = undefined,
    ?assertError(unknown_protocol,
                 mysql_protocol:handshake("foo", "bar", "baz", "db", mock_tcp,
                                          SSLOpts, Sock, false)),
    mock_tcp:close(Sock).

error_as_initial_packet_test() ->
    %% This behaviour has been observed from MariaDB 10.1.21
    PacketBody = <<255,16,4,84,111,111,32,109,97,110,121,32,99,111,110,110,101,
                   99,116,105,111,110,115>>,
    Packet = <<(byte_size(PacketBody)):24/little-integer,
               (_SeqNum = 0):8/integer, PacketBody/binary>>,
    Sock = mock_tcp:create([{recv, Packet}]),
    SSLOpts = undefined,
    ?assertMatch(#error{code = 1040, msg = <<"Too many connections">>},
                 mysql_protocol:handshake("foo", "bar", "baz", "db", mock_tcp,
                                          SSLOpts, Sock, false)),
    mock_tcp:close(Sock).

%% --- Helper functions for the above tests ---

%% Convert hex dumps to binaries. This is a helper function for the tests.
%% This function is also tested below.
hexdump_to_bin(HexDump) ->
    hexdump_to_bin(iolist_to_binary(HexDump), <<>>).

hexdump_to_bin(<<Line:50/binary, _Junk:20/binary, Rest/binary>>, Acc) ->
    hexdump_to_bin(Line, Rest, Acc);
hexdump_to_bin(<<Line:50/binary, _Junk/binary>>, Acc) ->
    %% last line (shorter than 70)
    hexdump_to_bin(Line, <<>>, Acc);
hexdump_to_bin(<<>>, Acc) ->
    Acc.

hexdump_to_bin(Line, Rest, Acc) ->
    HexNums = re:split(Line, <<"[ |]+">>, [{return, list}, trim]),
    Acc1 = lists:foldl(fun (HexNum, Acc0) ->
                           {ok, [Byte], []} = io_lib:fread("~16u", HexNum),
                           <<Acc0/binary, Byte:8>>
                       end,
                       Acc,
                       HexNums),
    hexdump_to_bin(Rest, Acc1).

hexdump_to_bin_test() ->
    HexDump =
        "0e 00 00 00 03 73 65 6c    65 63 74 20 55 53 45 52    .....select USER"
        "28 29                                                 ()",
    Expect = <<16#0e, 16#00, 16#00, 16#00, 16#03, 16#73, 16#65, 16#6c,
               16#65, 16#63, 16#74, 16#20, 16#55, 16#53, 16#45, 16#52,
               16#28, 16#29>>,
    ?assertEqual(Expect, hexdump_to_bin(HexDump)).
