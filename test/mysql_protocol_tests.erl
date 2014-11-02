%% @doc Eunit test cases for the mysql_protocol module.
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
    FakeSock = fakesocket_create(ExpectedCommunication),
    SendFun = fun (Data) -> fakesocket_send(FakeSock, Data) end,
    RecvFun = fun (Size) -> fakesocket_recv(FakeSock, Size) end,
    ResultSet = mysql_protocol:query(Query, SendFun, RecvFun),
    fakesocket_close(FakeSock),
    ?assertMatch(#text_resultset{column_definitions =
                                     [#column_definition{
                                          name = <<"@@version_comment">>}],
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
    Sock = fakesocket_create([{send, ExpectedReq}, {recv, ExpectedResponse}]),
    SendFun = fun (Data) -> fakesocket_send(Sock, Data) end,
    RecvFun = fun (Size) -> fakesocket_recv(Sock, Size) end,
    Result = mysql_protocol:query(Query, SendFun, RecvFun),
    ?assertMatch(#error{}, Result),
    fakesocket_close(Sock),
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
    Sock = fakesocket_create([{send, ExpectedReq}, {recv, ExpectedResp}]),
    SendFun = fun (Data) -> fakesocket_send(Sock, Data) end,
    RecvFun = fun (Size) -> fakesocket_recv(Sock, Size) end,
    Result = mysql_protocol:prepare(Query, SendFun, RecvFun),
    fakesocket_close(Sock),
    ?assertMatch(#prepared{statement_id = StmtId,
                           params = [#column_definition{name = <<"?">>},
                                     #column_definition{name = <<"?">>}],
                           columns = [#column_definition{name = <<"col1">>}],
                           warning_count = 0} when is_integer(StmtId),
                 Result),
    ok.
    

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

%% --- Fake socket ---
%%
%% A "fake socket" is used in test where we need to mock socket communication.
%% It is a pid maintaining a list of expected send and recv events.

%% @doc Creates a fakesocket process with a buffer of expected recv and send
%% calls. The pid of the fakesocket process is returned.
-spec fakesocket_create([{recv, binary()} | {send, binary()}]) -> pid().
fakesocket_create(ExpectedEvents) ->
    spawn_link(fun () -> fakesocket_loop(ExpectedEvents) end).

%% @doc Receives NumBytes bytes from fakesocket Pid. This function can be used
%% as a replacement for gen_tcp:recv/2 in unit tests. If there not enough data
%% in the fakesocket's buffer, an error is raised.
fakesocket_recv(Pid, NumBytes) ->
    Pid ! {recv, NumBytes, self()},
    receive
        {ok, Data} -> {ok, Data};
        error -> error({unexpected_recv, NumBytes})
    after 100 ->
        error(noreply)
    end.

%% @doc Sends data to fa fakesocket. This can be used as replacement for
%% gen_tcp:send/2 in unit tests. If the data sent is not what the fakesocket
%% expected, an error is raised.
fakesocket_send(Pid, Data) ->
    Pid ! {send, iolist_to_binary(Data), self()},
    receive
        ok -> ok;
        error -> error({unexpected_send, Data})
    after 100 ->
        error(noreply)
    end.

%% Stops the fakesocket process. If the fakesocket's buffer is not empty,
%% an error is raised.
fakesocket_close(Pid) ->
    Pid ! {done, self()},
    receive
        ok -> ok;
        {remains, Remains} -> error({unexpected_close, Remains})
    after 100 ->
        error(noreply)
    end.

%% Used by fakesocket_create/1.
fakesocket_loop(AllEvents = [{Func, Data} | Events]) ->
    receive
        {recv, NumBytes, FromPid} when Func == recv, NumBytes == size(Data) ->
            FromPid ! {ok, Data},
            fakesocket_loop(Events);
        {recv, NumBytes, FromPid} when Func == recv, NumBytes < size(Data) ->
            <<Data1:NumBytes/binary, Rest/binary>> = Data,
            FromPid ! {ok, Data1},
            fakesocket_loop([{recv, Rest} | Events]);
        {send, Bytes, FromPid} when Func == send, Bytes == Data ->
            FromPid ! ok,
            fakesocket_loop(Events);
        {send, Bytes, FromPid} when Func == send, size(Bytes) < size(Data) ->
            Size = size(Bytes),
            case Data of
                <<Bytes:Size/binary, Rest/binary>> ->
                    FromPid ! ok,
                    fakesocket_loop([{send, Rest} | Events]);
                _ ->
                    FromPid ! error
            end;
        {_, _, FromPid} ->
            FromPid ! error;
        {done, FromPid} ->
            FromPid ! {remains, AllEvents}
    end;
fakesocket_loop([]) ->
    receive
        {done, FromPid} -> FromPid ! ok;
        {_, _, FromPid} -> FromPid ! error
    end.

%% Tests for the fakesocket functions.
fakesocket_bad_recv_test() ->
    Pid = fakesocket_create([{recv, <<"foobar">>}]),
    ?assertError(_, fakesocket_recv(Pid, 10)).

fakesocket_success_test() ->
    Pid = fakesocket_create([{recv, <<"foobar">>}, {send, <<"baz">>}]),
    %?assertError({unexpected_close, _}, fakesocket_close(Pid)),
    ?assertEqual({ok, <<"foo">>}, fakesocket_recv(Pid, 3)),
    ?assertEqual({ok, <<"bar">>}, fakesocket_recv(Pid, 3)),
    ?assertEqual(ok, fakesocket_send(Pid, <<"baz">>)),
    ?assertEqual(ok, fakesocket_close(Pid)),
    %% The process will exit after close. Another recv will raise noreply.
    ?assertError(noreply, fakesocket_recv(Pid, 3)).
