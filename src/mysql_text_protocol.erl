%% @doc This module handles conversion of values in the form they are
%% represented in the text protocol to our prefered Erlang term representations.
-module(mysql_text_protocol).

-export([text_to_term/2]).

-include("records.hrl").
-include("protocol.hrl"). %% The TYPE_* macros.

%% @doc When receiving data in the text protocol, we get everything as binaries
%% (except NULL). This function is used to parse these strings values.
text_to_term(Type, Text) when is_binary(Text) ->
    case Type of
        ?TYPE_DECIMAL -> parse_float(Text); %% <-- this will probably change
        ?TYPE_TINY -> binary_to_integer(Text);
        ?TYPE_SHORT -> binary_to_integer(Text);
        ?TYPE_LONG -> binary_to_integer(Text);
        ?TYPE_FLOAT -> parse_float(Text);
        ?TYPE_DOUBLE -> parse_float(Text);
        ?TYPE_TIMESTAMP -> parse_datetime(Text);
        ?TYPE_LONGLONG -> binary_to_integer(Text);
        ?TYPE_INT24 -> binary_to_integer(Text);
        ?TYPE_DATE -> parse_date(Text);
        ?TYPE_TIME -> parse_time(Text);
        ?TYPE_DATETIME -> parse_datetime(Text);
        ?TYPE_YEAR -> binary_to_integer(Text);
        ?TYPE_VARCHAR -> Text;
        ?TYPE_BIT -> binary_to_integer(Text);
        ?TYPE_NEWDECIMAL -> parse_float(Text); %% <-- this will probably change
        ?TYPE_ENUM -> Text;
        ?TYPE_SET when Text == <<>> -> sets:new();
        ?TYPE_SET -> sets:from_list(binary:split(Text, <<",">>, [global]));
        ?TYPE_TINY_BLOB -> Text; %% charset?
        ?TYPE_MEDIUM_BLOB -> Text;
        ?TYPE_LONG_BLOB -> Text;
        ?TYPE_BLOB -> Text;
        ?TYPE_VAR_STRING -> Text;
        ?TYPE_STRING -> Text;
        ?TYPE_GEOMETRY -> Text %% <-- what do we want here?
    end;
text_to_term(_, null) ->
    %% NULL is the only value not represented as a binary.
    null.

parse_datetime(<<Y:4/binary, "-", M:2/binary, "-", D:2/binary, " ",
                 H:2/binary, ":", Mi:2/binary, ":", S:2/binary>>) ->
    {{binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)},
     {binary_to_integer(H), binary_to_integer(Mi), binary_to_integer(S)}}.

parse_date(<<Y:4/binary, "-", M:2/binary, "-", D:2/binary>>) ->
    {binary_to_integer(Y), binary_to_integer(M), binary_to_integer(D)}.

parse_time(<<H:2/binary, ":", Mi:2/binary, ":", S:2/binary>>) ->
    {binary_to_integer(H), binary_to_integer(Mi), binary_to_integer(S)}.

parse_float(Text) ->
    try binary_to_float(Text)
    catch error:badarg ->
        try binary_to_integer(Text) of
            Int -> float(Int)
        catch error:badarg ->
            %% It is something like "4e75" that must be turned into "4.0e75"
            binary_to_float(binary:replace(Text, <<"e">>, <<".0e">>))
        end
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

text_to_term_test() ->
    %% Int types
    lists:foreach(fun (T) -> ?assertEqual(1, text_to_term(T, <<"1">>)) end,
                  [?TYPE_TINY, ?TYPE_SHORT, ?TYPE_LONG, ?TYPE_LONGLONG,
                   ?TYPE_INT24, ?TYPE_YEAR, ?TYPE_BIT]),

    %% Floating point and decimal numbers
    lists:foreach(fun (T) -> ?assertEqual(3.0, text_to_term(T, <<"3.0">>)) end,
                  [?TYPE_FLOAT, ?TYPE_DOUBLE, ?TYPE_DECIMAL, ?TYPE_NEWDECIMAL]),
    ?assertEqual(3.0,  text_to_term(?TYPE_FLOAT, <<"3">>)),
    ?assertEqual(30.0, text_to_term(?TYPE_FLOAT, <<"3e1">>)),
    ?assertEqual(3,    text_to_term(?TYPE_LONG, <<"3">>)),

    %% Date and time
    ?assertEqual({2014, 11, 01}, text_to_term(?TYPE_DATE, <<"2014-11-01">>)),
    ?assertEqual({23, 59, 01}, text_to_term(?TYPE_TIME, <<"23:59:01">>)),
    ?assertEqual({{2014, 11, 01}, {23, 59, 01}},
                 text_to_term(?TYPE_DATETIME, <<"2014-11-01 23:59:01">>)),
    ?assertEqual({{2014, 11, 01}, {23, 59, 01}},
                 text_to_term(?TYPE_TIMESTAMP, <<"2014-11-01 23:59:01">>)),

    %% Strings and blobs
    lists:foreach(fun (T) ->
                      ?assertEqual(<<"x">>, text_to_term(T, <<"x">>))
                  end,
                  [?TYPE_VARCHAR, ?TYPE_ENUM, ?TYPE_TINY_BLOB,
                   ?TYPE_MEDIUM_BLOB, ?TYPE_LONG_BLOB, ?TYPE_BLOB,
                   ?TYPE_VAR_STRING, ?TYPE_STRING, ?TYPE_GEOMETRY]),

    %% Set
    ?assertEqual(sets:from_list([<<"b">>, <<"a">>]),
                 text_to_term(?TYPE_SET, <<"a,b">>)),
    ?assertEqual(sets:from_list([]), text_to_term(?TYPE_SET, <<>>)),

    %% NULL
    ?assertEqual(null, text_to_term(?TYPE_FLOAT, null)),
    ok.

-endif.
