%% @doc A logger report handler that be used to capture expected errors in
%% tests. The current error report handlers are disabled during the execution
%% of a function. Afterwards, they are restored and the errors that occered are
%% returned along with the return value of the fun.
-module(logger_acc).

%% Public API
-export([capture/1]).

%% @doc Executes `Fun' and captures all logged errors returns as well as
%% uncaught errors in `Fun'.
-spec capture(fun (() -> ResultOfFun)) ->
    {ok, ResultOfFun, AccumulatedErrors} |
    {throw | error | exit, Reason, Trace, AccumulatedErrors}
  when ResultOfFun :: term(),
       Reason :: term(),
       Trace :: list(),
       AccumulatedErrors :: [{logger:level(), [atom()], string()|logger:report()}].
capture(Fun) when is_function(Fun, 0) ->
    Tag = make_ref(),
    Self = self(),
    AccPid = spawn_link(fun() -> log_acc_loop(Tag, Self) end),
    logger:add_primary_filter(?MODULE, {fun(Event, _)-> AccPid ! {Tag, Event}, stop end, undefined}),
    try
        Fun()
    of
        Result ->
            Events = flush_logs(AccPid, Tag),
            {ok, Result, Events}
    catch
        Class:Error:Stacktrace ->
            Events = flush_logs(AccPid, Tag),
            {Class, Error, Stacktrace, Events}
    after
        ok = logger:remove_primary_filter(?MODULE)
    end.

flush_logs(AccPid, Tag) ->
    AccMon = monitor(process, AccPid),
    AccPid ! {Tag, flush},
    receive
        {Tag, Events} ->
            demonitor(AccMon, [flush]),
            Events;
        {'DOWN', AccMon, process, AccPid, Reason} ->
            error({accumulator_process, Reason})
    end.

log_acc_loop(Tag, Parent) ->
    log_acc_loop(Tag, Parent, open, []).

log_acc_loop(Tag, Parent, Status, Acc) ->
    Timeout = case Status of
                  open -> infinity;
                  closing -> 1000
              end,
    receive
        {Tag, flush} when Status =:= open ->
            log_acc_loop(Tag, Parent, closing, Acc);
        {Tag, #{level := Level, msg := Msg} = Event} ->
            Domain = case Event of
                         #{meta := #{domain := Dom}} -> Dom;
                         #{} -> []
                     end,
            Message = case Msg of
                          {string, Str} -> unicode:characters_to_list(Str);
                          {report, Report} -> Report;
                          {Fmt, Args} -> lists:flatten(io_lib:format(Fmt, Args))
                      end,
            log_acc_loop(Tag, Parent, Status, [{Level, Domain, Message} | Acc]);
        Other ->
            error({unexpected_message, Other})
    after Timeout ->
        Parent ! {Tag, lists:reverse(Acc)},
        unlink(Parent),
        ok
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

capture_success_test() ->
    Result = ?MODULE:capture(fun() ->
                                 logger:notice("Hello ~p", [world]),
                                 logger:notice("Hello ~p", [again]),
                                 foo
                             end),
    ?assertEqual({ok, foo, [{notice, [], "Hello world"}, {notice, [], "Hello again"}]}, Result).

capture_failure_test() ->
    Result = ?MODULE:capture(fun() ->
                                 logger:notice("Hello ~p", [world]),
                                 throw(foo)
                             end),
    ?assertMatch({throw, foo, _Trace, [{notice, [], "Hello world"}]}, Result).

-endif.
