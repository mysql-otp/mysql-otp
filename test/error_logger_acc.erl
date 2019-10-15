%% @doc A error_logger report handler that be used to capture expected errors in
%% tests. The current error report handlers are disabled during the execution
%% of a function. Afterwards, they are restored and the errors that occered are
%% returned along with the return value of the fun.
%%
%% This module was created before OTP 21 when logger didn't exist. Logger
%% support has been added later, but the log entries are still returned in the
%% old error_logger format. Logger events which are not backwards compatible
%% with error_logger are silently ignored, which is OK as long as only OTP
%% proc_lib based processes are crashing and explicit logging is done via
%% error_logger.
%%
%% TODO: Use logger by default and use error_logger only for old OTP releases.
-module(error_logger_acc).

-include("exception.hrl").

%% Public API
-export([capture/1]).

-behaviour(gen_event).
-export([init/1, handle_event/2, handle_call/2, handle_info/2, terminate/2,
         code_change/3]).

%% @doc Executes `Fun' and captures all logged errors returns as well as
%% uncaught errors in `Fun'.
-spec capture(fun (() -> ResultOfFun)) ->
    {ok, ResultOfFun, AccumulatedErrors} |
    {throw | error | exit, Reason, Trace, AccumulatedErrors}
  when ResultOfFun :: term(),
       Reason :: term(),
       Trace :: list(),
       AccumulatedErrors :: [{error|warning_msg|info_msg, string()} |
                             {error_report|warning_report|info_report, term()}].
capture(Fun) when is_function(Fun, 0) ->
    %% From OTP 21.0, error_logger is no longer started by default, but is
    %% automatically started when an event handler is added with
    %% error_logger:add_report_handler/1,2. The error_logger module is then
    %% also added as a handler to the new logger.
    error_logger:add_report_handler(?MODULE),
    OldHandlers = gen_event:which_handlers(error_logger) -- [?MODULE],
    lists:foreach(fun error_logger:delete_report_handler/1, OldHandlers),
    DefaultLoggerHandler = remove_default_logger_handler(),
    try Fun() of
        Result ->
            lists:foreach(fun error_logger:add_report_handler/1, OldHandlers),
            restore_default_logger_handler(DefaultLoggerHandler),
            {ok, Result, error_logger:delete_report_handler(?MODULE)}
    catch
        ?EXCEPTION(Class, Error, Stacktrace) ->
            lists:foreach(fun error_logger:add_report_handler/1, OldHandlers),
            AccumulatedErrors = error_logger:delete_report_handler(?MODULE),
            restore_default_logger_handler(DefaultLoggerHandler),
            {Class, Error, ?GET_STACK(Stacktrace), AccumulatedErrors}
    end.

%% --- gen_event callbacks ---

init([]) ->
    {ok, []}.

handle_event({ErrorType, _Gleader, {_Pid, Format, Data}}, State) ->
    ShortError = if
        ErrorType == error; ErrorType == warning_msg; ErrorType == info_msg ->
            {ErrorType, lists:flatten(io_lib:format(Format, Data))};
        true ->
            {ErrorType, {Format, Data}}
    end,
    {ok, [ShortError | State]};
handle_event(_OtherEvent, State) ->
    {ok, State}.

handle_call(_Call, State) ->
    {ok, ignored, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate([], State) ->
    %% error_logger:delete_report_handler/1 called
    lists:reverse(State);
terminate(_Arg, _State) ->
    %% terminating for some other reason.
    error_logger:info_msg("Accumulating error handler shutting down"),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-ifdef(OTP_RELEASE).

remove_default_logger_handler() ->
    {ok, Config} = logger:get_handler_config(default),
    ok = logger:remove_handler(default),
    Config.

restore_default_logger_handler(#{id := Id, module := Module} = Config) ->
    logger:add_handler(Id, Module, Config).

-else.

remove_default_logger_handler() -> none.

restore_default_logger_handler(none) -> ok.

-endif.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

capture_success_test() ->
    Result = ?MODULE:capture(fun () ->
        error_logger:info_msg("Hello ~p", [world]),
        error_logger:info_msg("Hello ~p", [again]),
        foo
    end),
    ?assertEqual({ok, foo, [{info_msg, "Hello world"}, {info_msg, "Hello again"}]}, Result).

capture_failure_test() ->
    Result = ?MODULE:capture(fun () ->
        error_logger:info_msg("Hello ~p", [world]),
        throw(foo)
    end),
    ?assertMatch({throw, foo, _Trace, [{info_msg, "Hello world"}]}, Result).

-endif.
