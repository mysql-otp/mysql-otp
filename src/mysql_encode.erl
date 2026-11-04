%% @private
%% @doc Functions for encoding a term as an SQL literal. This is not really
%% part of the protocol; thus the separate module.
-module(mysql_encode).

-export([encode/1, backslash_escape/1, split_seconds/1]).

%% @doc Encodes a term as an ANSI SQL literal so that it can be used inside
%% a query. In strings only single quotes (') are escaped. If backslash escapes
%% are enabled for the connection, you should first use backslash_escape/1 to
%% escape backslashes in strings.
-spec encode(term()) -> iodata().
encode(null) -> <<"NULL">>;
encode(Int) when is_integer(Int) ->
    integer_to_binary(Int);
encode(Float) when is_float(Float) ->
    %% "floats are printed accurately as the shortest, correctly rounded string"
    io_lib:format("~w", [Float]);
encode(Bin) when is_binary(Bin) ->
    Escaped = binary:replace(Bin, <<"'">>, <<"''">>, [global]),
    [$', Escaped, $'];
encode(String) when is_list(String) ->
    case unicode:characters_to_binary(String) of
        Bin when is_binary(Bin) -> encode(Bin);
        _ -> error(badarg)
    end;
encode(Bitstring) when is_bitstring(Bitstring) ->
    ["b'", [ case B of 0 -> $0; 1 -> $1 end || <<B:1>> <= Bitstring ], $'];
encode({decimal, Num}) when is_float(Num); is_integer(Num) ->
    encode(Num);
encode({decimal, Str}) when is_binary(Str); is_list(Str) ->
    case re:run(Str, <<"\\A[+-]?(\\d+(\\.\\d*)?|\\.\\d+)([eE][+-]?\\d+)?\\z">>,
                [{capture, none}]) of
        match -> Str;
        nomatch -> error(badarg)
    end;
encode({Y, M, D}) ->
    io_lib:format("'~4..0b-~2..0b-~2..0b'", [Y, M, D]);
encode({{Y, M, D}, {H, Mi, S}}) when is_integer(S) ->
    io_lib:format("'~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b'",
                  [Y, M, D, H, Mi, S]);
encode({{Y, M, D}, {H, Mi, S}}) when is_float(S) ->
    {Sec, Micro} = split_seconds(S),
    io_lib:format("'~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b.~6..0b'",
                  [Y, M, D, H, Mi, Sec, Micro]);
encode({D, {H, M, S}}) when D >= 0, is_integer(S) ->
    H1 = D * 24 + H,
    Args = [H1, M, S],
    if
        H1 > 99 -> io_lib:format("'~b:~2..0b:~2..0b'", Args);
        true    -> io_lib:format("'~2..0b:~2..0b:~2..0b'", Args)
    end;
encode({D, {H, M, S}}) when D >= 0, is_float(S) ->
    H1 = D * 24 + H,
    {Sec, Micro} = split_seconds(S),
    Args = [H1, M, Sec, Micro],
    if
        H1 > 99 -> io_lib:format("'~b:~2..0b:~2..0b.~6..0b'", Args);
        true    -> io_lib:format("'~2..0b:~2..0b:~2..0b.~6..0b'", Args)
    end;
encode({D, {H, M, S}}) when D < 0, is_integer(S) ->
    Sec = (D * 24 + H) * 3600 + M * 60 + S,
    {D1, {H1, M1, S1}} = calendar:seconds_to_daystime(-Sec),
    H2 = D1 * 24 + H1,
    Args = [H2, M1, S1],
    if
        H2 > 99 -> io_lib:format("'-~b:~2..0b:~2..0b'", Args);
        true    -> io_lib:format("'-~2..0b:~2..0b:~2..0b'", Args)
    end;
encode({D, {H, M, S}}) when D < 0, is_float(S) ->
    %% Split the absolute value, e.g. -1 day + 23:59:57.654321 = -2.345679 s
    {Sec, Micro} = split_seconds(-((D * 24 + H) * 3600 + M * 60 + S)),
    {D1, {H1, M1, S1}} = calendar:seconds_to_daystime(Sec),
    H2 = D1 * 24 + H1,
    Args = [H2, M1, S1, Micro],
    if
        H2 > 99 -> io_lib:format("'-~b:~2..0b:~2..0b.~6..0b'", Args);
        true    -> io_lib:format("'-~2..0b:~2..0b:~2..0b.~6..0b'", Args)
    end.

%% @doc Splits non-negative fractional seconds into whole seconds and
%% microseconds. Fractions that would round up to a whole second are capped
%% at 999999 microseconds.
-spec split_seconds(float()) -> {non_neg_integer(), 0..999999}.
split_seconds(S) when is_float(S), S >= 0 ->
    Sec = trunc(S),
    {Sec, min(round((S - Sec) * 1000000), 999999)}.

%% @doc Escapes backslashes with an extra backslash. This is necessary if
%% backslash escapes are enabled in the session.
backslash_escape(Bin) when is_binary(Bin) ->
    binary:replace(Bin, <<"\\">>, <<"\\\\">>, [global]);
backslash_escape(String) when is_list(String) ->
    case unicode:characters_to_binary(String) of
        Bin when is_binary(Bin) -> backslash_escape(Bin);
        _ -> error(badarg)
    end.
