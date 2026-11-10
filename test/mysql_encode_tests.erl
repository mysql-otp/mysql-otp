%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014-2015, 2021 Viktor Söderqvist
%%               2026 Maria Scott
%%
%% This file is part of MySQL/OTP.
%%
%% MySQL/OTP is free software: you can redistribute it and/or modify it under
%% the terms of the GNU Lesser General Public License as published by the Free
%% Software Foundation, either version 3 of the License, or (at your option)
%% any later version.
%%
%% This program is distributed in the hope that it will be useful, but WITHOUT
%% ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
%% FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
%% more details.
%%
%% You should have received a copy of the GNU Lesser General Public License
%% along with this program. If not, see <https://www.gnu.org/licenses/>.

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

microsecond_rounding_test() ->
    %% Fractions that would round up to a whole second are capped at
    %% 999999 microseconds instead of carrying over.
    lists:foreach(
        fun ({Term, Sql}) ->
            ?assertEqual(iolist_to_binary(Sql),
                         iolist_to_binary(mysql_encode:encode(Term)))
        end,
        [{{{2014, 12, 31}, {23, 59, 59.9999997}}, "'2014-12-31 23:59:59.999999'"},
         {{{9999, 12, 31}, {23, 59, 59.9999997}}, "'9999-12-31 23:59:59.999999'"},
         {{{2014, 2, 30}, {23, 59, 59.9999997}},  "'2014-02-30 23:59:59.999999'"},
         {{0, {23, 59, 59.9999997}},              "'23:59:59.999999'"},
         {{5, {0, 0, 59.9999997}},                "'120:00:59.999999'"},
         {{-1, {0, 0, 0.0000003}},                "'-23:59:59.999999'"},
         {{-5, {0, 0, 0.0000003}},                "'-119:59:59.999999'"}]).

decimal_test() ->
    lists:foreach(
        fun (Str) ->
            ?assertEqual(iolist_to_binary(Str),
                         iolist_to_binary(mysql_encode:encode({decimal, Str})))
        end,
        ["10.2", <<"-10.2">>, "+1", "123.", ".5", "1e3", "1.5E-3", "-.5e+10"]).

decimal_invalid_test() ->
    lists:foreach(
        fun (Str) ->
            ?assertError(badarg, mysql_encode:encode({decimal, Str}))
        end,
        [<<>>, <<".">>, <<"e">>, <<"1e">>, <<"1--">>, <<"--1">>, <<"- 5">>,
         <<"1.2.3">>, <<"1e5e5">>, <<"+-.">>, <<"1 OR 1">>, <<"1\n">>,
         [8364]]).

backslash_escape_test() ->
    ?assertEqual(<<"a'b\\\\c'd\\\\e">>,
                 iolist_to_binary(mysql_encode:backslash_escape("a'b\\c'd\\e"))).

backslash_escape_unicode_test() ->
    %% Unicode codepoints in lists get encoded as UTF-8, as in encode/1
    ?assertEqual(<<"Caf", 195, 169>>,
                 iolist_to_binary(mysql_encode:backslash_escape("Café"))),
    ?assertEqual(<<"100 ", 226, 130, 172>>,
                 iolist_to_binary(mysql_encode:backslash_escape("100 €"))),
    ?assertEqual(<<"a\\\\b", 195, 169>>,
                 iolist_to_binary(mysql_encode:backslash_escape("a\\bé"))),
    %% Binaries are not converted
    ?assertEqual(<<255, 0>>,
                 iolist_to_binary(mysql_encode:backslash_escape(<<255, 0>>))),
    ?assertError(badarg, mysql_encode:backslash_escape([16#110000])).
