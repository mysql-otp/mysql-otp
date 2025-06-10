%% @doc A module to be used where gen_tcp is expected.
%%
%% A "fake socket" is used in test where we need to mock socket communication.
%% It is a pid maintaining a list of expected send and recv events.
-module(mock_tcp).

%% gen_tcp interface functions.
-export([send/2, recv/2, recv/3, close/1]).

%% Functions to setup the mock_tcp.
-export([expect/1, disconnected/0]).
-export([with_mock/2]).
-export([stop/1]).

%% @doc Runs the given function `Fun' with the given mock_tcp process
%% as argument and returns the result. Makes sure that the given process
%% is properly stopped afterwards.
-spec with_mock(MockPid, fun((MockPid) -> Result)) -> Result
    when MockPid :: pid(),
         Result :: term().
with_mock(MockPid, Fun) when is_pid(MockPid), is_function(Fun, 1) ->
    try
        Fun(MockPid)
    after
        ok = stop(MockPid)
    end.

%% @doc Creates a mock_tcp process with a buffer of expected recv/2,3 and send/2
%% calls. The pid of the mock_tcp process is returned.
-spec expect([{recv, binary()} | {send, binary() | 'ignore'} | 'disconnect']) -> pid().
expect(ExpectedEvents) when is_list(ExpectedEvents) ->
    spawn_link(fun () -> expect_loop(ExpectedEvents) end).

%% @doc Creates a mock_tcp process that simulates that it is closed by returning
%% `{error, closed}' to all recv/2,3 and send/2 calls. The pid of the mock_tcp
%% process is returned.
-spec disconnected() -> pid().
disconnected() ->
    spawn_link(fun() -> disconnected_loop(false) end).

%% @doc Receives NumBytes bytes from mock_tcp Pid. This function can be used
%% as a replacement for gen_tcp:recv/2 in unit tests. If there not enough data
%% in the mock_tcp's buffer, an error is raised.
recv(Pid, NumBytes) ->
    call(Pid, {recv, NumBytes}).

recv(Pid, NumBytes, _Timeout) ->
    recv(Pid, NumBytes).

%% @doc Sends data to a mock_tcp. This can be used as replacement for
%% gen_tcp:send/2 in unit tests. If the data sent is not what the mock_tcp
%% expected, an error is raised.
send(Pid, Data) ->
    call(Pid, {send, iolist_to_binary(Data)}).

%% Closes a mock_tcp. If the mock_tcp's buffer is not empty,
%% an error is raised. Note that the mock_tcp process is not
%% stopped.
close(Pid) ->
    call(Pid, close).

%% Stops the mock_tcp process. Always returns `ok'.
stop(Pid) ->
    Mon = monitor(process, Pid),
    Pid ! stop,
    receive
        {'DOWN', Mon, process, Pid, _Reason} -> ok
    after 1000 ->
        error(not_stopped)
    end,
    ok.

call(Pid, Msg) ->
    Tag = make_ref(),
    Pid ! {{self(), Tag}, Msg},
    receive
        {Tag, reply, Reply} -> Reply;
        {Tag, error, Msg} -> error(Msg)
    after 100 ->
        error(noreply)
    end.

%% Used by expect/1.
expect_loop([disconnect]) ->
    disconnected_loop(false);
expect_loop(AllEvents = [{Func, Data} = Event | Events]) ->
    receive
        stop ->
            ok;
        {ReplyTo, {recv, NumBytes}} when Func =:= recv, NumBytes =:= byte_size(Data) ->
            reply(ReplyTo, reply, {ok, Data}),
            expect_loop(Events);
        {ReplyTo, {recv, NumBytes}} when Func =:= recv, NumBytes < byte_size(Data) ->
            <<Data1:NumBytes/binary, Rest/binary>> = Data,
            reply(ReplyTo, reply, {ok, Data1}),
            expect_loop([{recv, Rest} | Events]);
        {ReplyTo, {send, _Bytes}} when Func =:= send, Data =:= ignore ->
            reply(ReplyTo, reply, ok),
            expect_loop(Events);
        {ReplyTo, {send, Bytes}} when Func =:= send, Bytes =:= Data ->
            reply(ReplyTo, reply, ok),
            expect_loop(Events);
        {ReplyTo, {send, Bytes} = CmdData} when Func == send, byte_size(Bytes) < byte_size(Data) ->
            Size = byte_size(Bytes),
            case Data of
                <<Bytes:Size/binary, Rest/binary>> ->
                    reply(ReplyTo, reply, ok),
                    expect_loop([{send, Rest} | Events]);
                _ ->
                    reply(ReplyTo, error, {unexpected, CmdData, Event}),
                    expect_loop(Events)
            end;
        {ReplyTo, close} ->
            reply(ReplyTo, error, {unexpected, close, AllEvents}),
            expect_loop_closed();
        {ReplyTo, CmdData} ->
            reply(ReplyTo, error, {unexpected, CmdData, Event}),
            expect_loop(Events)
    end;
expect_loop([]) ->
    receive
        stop ->
            ok;
        {ReplyTo, close} ->
            reply(ReplyTo, reply, ok),
            expect_loop_closed();
        {ReplyTo, CmdData} ->
            reply(ReplyTo, error, {unexpected, CmdData}),
            expect_loop([])
    end.

expect_loop_closed() ->
    receive
        stop ->
            ok;
        {ReplyTo, close} ->
            reply(ReplyTo, reply, ok),
            expect_loop_closed();
        {ReplyTo, CmdData} ->
            reply(ReplyTo, error, {unexpected, CmdData}),
            expect_loop_closed()
    end.

%% Used by disconnected/0.
disconnected_loop(Recvd) ->
    receive
        stop ->
            ok;
        {ReplyTo, close} ->
            reply(ReplyTo, reply, ok),
            disconnected_loop(Recvd);
        {ReplyTo, {recv, _NumBytes}} ->
            reply(ReplyTo, reply, {error, closed}),
            disconnected_loop(true);
        {ReplyTo, {send, _Bytes}} when Recvd ->
            reply(ReplyTo, reply, {error, closed}),
            disconnected_loop(Recvd);
        {ReplyTo, {send, _Bytes}} ->
            reply(ReplyTo, reply, ok),
            disconnected_loop(Recvd)
    end.

reply({Pid, Tag}, Type, Msg) ->
    Pid ! {Tag, Type, Msg}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Tests for the mock_tcp functions.
bad_recv_test() ->
    Pid = expect([{recv, <<"foobar">>}]),
    ?assertError(_, recv(Pid, 10)).

success_test() ->
    Pid = expect([{recv, <<"foobar">>}, {send, <<"baz">>}]),
    %?assertError({unexpected_close, _}, close(Pid)),
    ?assertEqual({ok, <<"foo">>}, recv(Pid, 3)),
    ?assertEqual({ok, <<"bar">>}, recv(Pid, 3)),
    ?assertEqual(ok, send(Pid, <<"baz">>)),
    ?assertEqual(ok, close(Pid)),
    %% The process will exit after close. Another recv will raise noreply.
    ?assertError(noreply, recv(Pid, 3)).
-endif.
