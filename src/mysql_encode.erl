%% @private
%% @doc Functions for encoding a term as an SQL literal. This is not really
%% part of the protocol; thus the separate module.
-module(mysql_encode).

-export([encode/1, backslash_escape/1]).

%% @doc Encodes a term as an ANSI SQL literal so that it can be used to inside
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
    encode(unicode:characters_to_binary(String));
encode(Bitstring) when is_bitstring(Bitstring) ->
    ["b'", [ case B of 0 -> $0; 1 -> $1 end || <<B:1>> <= Bitstring ], $'];
encode({decimal, Num}) when is_float(Num); is_integer(Num) ->
    encode(Num);
encode({decimal, Str}) when is_binary(Str); is_list(Str) ->
    %% Simple injection block
    nomatch = re:run(Str, <<"[^0-9.+\\-eE]">>),
    Str;
encode({Y, M, D}) ->
    io_lib:format("'~4..0b-~2..0b-~2..0b'", [Y, M, D]);
encode({{Y, M, D}, {H, Mi, S}}) when is_integer(S) ->
    io_lib:format("'~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~2..0b'",
                  [Y, M, D, H, Mi, S]);
encode({{Y, M, D}, {H, Mi, S}}) when is_float(S) ->
    io_lib:format("'~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~9.6.0f'",
                  [Y, M, D, H, Mi, S]);
encode({D, {H, M, S}}) when D >= 0 ->
    Args = [H1 = D * 24 + H, M, S],
    if
        H1 > 99, is_integer(S) -> io_lib:format("'~b:~2..0b:~2..0b'", Args);
        H1 > 99, is_float(S)   -> io_lib:format("'~b:~2..0b:~9.6.0f'", Args);
        is_integer(S)          -> io_lib:format("'~2..0b:~2..0b:~2..0b'", Args);
        is_float(S)            -> io_lib:format("'~2..0b:~2..0b:~9.6.0f'", Args)
    end;
encode({D, {H, M, S}}) when D < 0, is_integer(S) ->
    Sec = (D * 24 + H) * 3600 + M * 60 + S,
    {D1, {H1, M1, S1}} = calendar:seconds_to_daystime(-Sec),
    Args = [H2 = D1 * 24 + H1, M1, S1],
    if
        H2 > 99 -> io_lib:format("'-~b:~2..0b:~2..0b'", Args);
        true    -> io_lib:format("'-~2..0b:~2..0b:~2..0b'", Args)
    end;
encode({D, {H, M, S}}) when D < 0, is_float(S) ->
    SInt = trunc(S), % trunc(57.654321) = 57
    {SInt1, Frac} = case S - SInt of % 57.6543 - 57 = 0.654321
        0.0  -> {SInt, 0.0};
        Rest -> {SInt + 1, 1 - Rest} % {58, 0.345679}
    end,
    Sec = (D * 24 + H) * 3600 + M * 60 + SInt1,
    {D1, {H1, M1, S1}} = calendar:seconds_to_daystime(-Sec),
    Args = [H2 = D1 * 24 + H1, M1, S1 + Frac],
    if
        H2 > 99 -> io_lib:format("'-~b:~2..0b:~9.6.0f'", Args);
        true    -> io_lib:format("'-~2..0b:~2..0b:~9.6.0f'", Args)
    end.

%% @doc Escapes backslashes with an extra backslash. This is necessary if
%% backslash escapes are enabled in the session.
backslash_escape(String) ->
    Bin = iolist_to_binary(String),
    binary:replace(Bin, <<"\\">>, <<"\\\\">>, [global]).
