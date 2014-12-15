%% @doc A module to be used where gen_tcp is expected.
%%
%% A "fake socket" is used in test where we need to mock socket communication.
%% It is a pid maintaining a list of expected send and recv events.
-module(mock_tcp).

%% gen_tcp interface functions.
-export([send/2, recv/2, recv/3]).

%% Functions to setup the mock_tcp.
-export([create/1, close/1]).

%% @doc Creates a mock_tcp process with a buffer of expected recv/2,3 and send/2
%% calls. The pid of the mock_tcp process is returned.
-spec create([{recv, binary()} | {send, binary()}]) -> pid().
create(ExpectedEvents) ->
    spawn_link(fun () -> loop(ExpectedEvents) end).

%% @doc Receives NumBytes bytes from mock_tcp Pid. This function can be used
%% as a replacement for gen_tcp:recv/2 in unit tests. If there not enough data
%% in the mock_tcp's buffer, an error is raised.
recv(Pid, NumBytes) ->
    Pid ! {recv, NumBytes, self()},
    receive
        {ok, Data} -> {ok, Data};
        error -> error({unexpected_recv, NumBytes})
    after 100 ->
        error(noreply)
    end.

recv(Pid, NumBytes, _Timeout) ->
    recv(Pid, NumBytes).

%% @doc Sends data to a mock_tcp. This can be used as replacement for
%% gen_tcp:send/2 in unit tests. If the data sent is not what the mock_tcp
%% expected, an error is raised.
send(Pid, Data) ->
    Pid ! {send, iolist_to_binary(Data), self()},
    receive
        ok -> ok;
        error -> error({unexpected_send, Data})
    after 100 ->
        error(noreply)
    end.

%% Stops the mock_tcp process. If the mock_tcp's buffer is not empty,
%% an error is raised.
close(Pid) ->
    Pid ! {done, self()},
    receive
        ok -> ok;
        {remains, Remains} -> error({unexpected_close, Remains})
    after 100 ->
        error(noreply)
    end.

%% Used by create/1.
loop(AllEvents = [{Func, Data} | Events]) ->
    receive
        {recv, NumBytes, FromPid} when Func == recv, NumBytes == size(Data) ->
            FromPid ! {ok, Data},
            loop(Events);
        {recv, NumBytes, FromPid} when Func == recv, NumBytes < size(Data) ->
            <<Data1:NumBytes/binary, Rest/binary>> = Data,
            FromPid ! {ok, Data1},
            loop([{recv, Rest} | Events]);
        {send, Bytes, FromPid} when Func == send, Bytes == Data ->
            FromPid ! ok,
            loop(Events);
        {send, Bytes, FromPid} when Func == send, size(Bytes) < size(Data) ->
            Size = size(Bytes),
            case Data of
                <<Bytes:Size/binary, Rest/binary>> ->
                    FromPid ! ok,
                    loop([{send, Rest} | Events]);
                _ ->
                    FromPid ! error
            end;
        {_, _, FromPid} ->
            FromPid ! error;
        {done, FromPid} ->
            FromPid ! {remains, AllEvents}
    end;
loop([]) ->
    receive
        {done, FromPid} -> FromPid ! ok;
        {_, _, FromPid} -> FromPid ! error
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Tests for the mock_tcp functions.
bad_recv_test() ->
    Pid = create([{recv, <<"foobar">>}]),
    ?assertError(_, recv(Pid, 10)).

success_test() ->
    Pid = create([{recv, <<"foobar">>}, {send, <<"baz">>}]),
    %?assertError({unexpected_close, _}, close(Pid)),
    ?assertEqual({ok, <<"foo">>}, recv(Pid, 3)),
    ?assertEqual({ok, <<"bar">>}, recv(Pid, 3)),
    ?assertEqual(ok, send(Pid, <<"baz">>)),
    ?assertEqual(ok, close(Pid)),
    %% The process will exit after close. Another recv will raise noreply.
    ?assertError(noreply, recv(Pid, 3)).
-endif.
