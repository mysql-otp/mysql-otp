-module(mock_log_fun).
-export([log_callback/3]).

log_callback(_Level, Msg, Args) ->
    error_logger:warning_msg(Msg, Args).
