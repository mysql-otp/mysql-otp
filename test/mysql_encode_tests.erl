%% coding: utf-8
%% @doc This test suite does not require an actual MySQL connection.
-module(mysql_encode_tests).
-include_lib("eunit/include/eunit.hrl").

encode_test() ->
    lists:foreach(
        fun ({Term, Sql}) ->
            ?assertEqual(iolist_to_binary(Sql),
                         iolist_to_binary(mysql_encode:encode(Term)))
        end,
        [{null,    "NULL"},
         {42,      "42"},
         {3.14,    "3.14"},
         {"isn't didn't", "'isn''t didn''t'"}, %% Escape single quotes.
         {"\\n",   "'\\n'"},                   %% Don't escape backslash.
         %% Unicode codepoints gets encoded as UTF-8
         {[<<"asdf">>, "ščžć€"],
          <<"'asdf",197,161,196,141,197,190,196,135,226,130,172,"'">>},
         %% Non-Unicode binary
         {<<255, 0, 255, 0>>, <<"'", 255, 0, 255, 0, "'">>},
         %% BIT(N)
         {<<255, 2:3>>,   "b'11111111010'"},
         %% Explicit decimal
         {{decimal, 10.2}, "10.2"},
         {{decimal, "10.2"}, "10.2"},
         %% DATE
         {{2014, 11, 03}, "'2014-11-03'"},
         {{0, 0, 0},      "'0000-00-00'"},
         %% TIME
         {{0, {10, 11, 12}},   "'10:11:12'"},
         {{5, {0, 0, 1}},     "'120:00:01'"},
         {{-1, {23, 59, 59}}, "'-00:00:01'"},
         {{-1, {23, 59, 0}},  "'-00:01:00'"},
         {{-1, {23, 0, 0}},   "'-01:00:00'"},
         {{-1, {0, 0, 0}},    "'-24:00:00'"},
         {{-5, {10, 0, 0}},  "'-110:00:00'"},
         {{0, {0, 0, 0}},      "'00:00:00'"},
         %% TIME with microseconds
         {{0, {23, 59, 57.654321}},   "'23:59:57.654321'"},
         {{5, {0, 0, 1.1}},          "'120:00:01.100000'"},
         {{-1, {23, 59, 57.654321}}, "'-00:00:02.345679'"},
         {{-1, {23, 59,  0.0}},      "'-00:01:00.000000'"},
         {{-6, {23, 59, 57.0}},     "'-120:00:03.000000'"},
         %% DATETIME
         {{{2014, 12, 14}, {19, 39, 20}},   "'2014-12-14 19:39:20'"},
         {{{2014, 12, 14}, {0, 0, 0}},      "'2014-12-14 00:00:00'"},
         {{{0, 0, 0}, {0, 0, 0}},           "'0000-00-00 00:00:00'"},
         %% DATETIME with microseconds
         {{{2014, 11, 23}, {23, 59, 57.654321}}, "'2014-11-23 23:59:57.654321'"}]
    ).

backslash_escape_test() ->
    ?assertEqual(<<"a'b\\\\c'd\\\\e">>,
                 iolist_to_binary(mysql_encode:backslash_escape("a'b\\c'd\\e"))).
