%% Minicache. Feel free to rename this module and include it in other projects.
%%-----------------------------------------------------------------------------
%% Copyright 2014 Viktor Söderqvist
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

%% @doc A minimalistic time triggered dict based cache data structure.
%%
%% The cache keeps track of when each key was last used. Elements are evicted
%% using manual calls to evict_older_than/2. Most of the functions return a new
%% updated cache object which should be used in subsequent calls.
%%
%% A cache can be initialized to 'empty' which represents the empty cache.
%%
%% Properties:
%%
%% <ul>
%%   <li>Embeddable in a gen_server or other process</li>
%%   <li>Small overhead when unused (the empty cache is a single atom)</li>
%%   <li>Evicting K elements is O(N + K * log N) which means low overhead when
%%       nothing or few elements are evicted</li>
%% </ul>
%% @private
-module(mysql_cache).

-export_type([cache/2]).
-export([evict_older_than/2, lookup/2, new/0, size/1, store/3]).

-type cache(K, V) ::
    {cache, erlang:timestamp(), dict:dict(K, {V, non_neg_integer()})} | empty.

%% @doc Deletes the entries that have not been used for `MaxAge' milliseconds
%% and returns them along with the new state.
-spec evict_older_than(Cache :: cache(K, V), MaxAge :: non_neg_integer()) ->
    {Evicted :: [{K, V}], NewCache :: cache(K, V)}.
evict_older_than({cache, StartTs, Dict}, MaxAge) ->
    MinTime = timer:now_diff(os:timestamp(), StartTs) div 1000 - MaxAge,
    {Evicted, Dict1} = dict:fold(
        fun (Key, {Value, Time}, {EvictedAcc, DictAcc}) ->
            if
                Time < MinTime ->
                    {[{Key, Value} | EvictedAcc], dict:erase(Key, DictAcc)};
                Time >= MinTime ->
                    {EvictedAcc, DictAcc}
            end
        end,
        {[], Dict},
        Dict),
    Cache1 = case dict:size(Dict1) of
        0 -> empty;
        _ -> {cache, StartTs, Dict1}
    end,
    {Evicted, Cache1};
evict_older_than(empty, _) ->
    {[], empty}.

%% @doc Looks up a key in a cache. If found, returns the value and a new cache
%% with the 'last used' timestamp updated for the key.
-spec lookup(Key :: K, Cache :: cache(K, V)) ->
    {found, Value :: V, UpdatedCache :: cache(K, V)} | not_found.
lookup(Key, {cache, StartTs, Dict}) ->
    case dict:find(Key, Dict) of
        {ok, {Value, _OldTime}} ->
            NewTime = timer:now_diff(os:timestamp(), StartTs) div 1000,
            Dict1 = dict:store(Key, {Value, NewTime}, Dict),
            Cache1 = {cache, StartTs, Dict1},
            {found, Value, Cache1};
        error ->
            not_found
    end;
lookup(_Key, empty) ->
    not_found.

%% @doc Returns the atom `empty' which represents an empty cache.
-spec new() -> cache(K :: term(), V :: term()).
new() ->
    empty.

%% @doc Returns the number of elements in the cache.
-spec size(cache(K :: term(), V :: term())) -> non_neg_integer().
size({cache, _, Dict}) ->
    dict:size(Dict);
size(empty) ->
    0.

%% @doc Stores a key-value pair in the cache. If the key already exists, the
%% associated value is replaced by `Value'.
-spec store(Key :: K, Value :: V, Cache :: cache(K, V)) -> cache(K, V)
    when K :: term(), V :: term().
store(Key, Value, {cache, StartTs, Dict}) ->
    Time = timer:now_diff(os:timestamp(), StartTs) div 1000,
    {cache, StartTs, dict:store(Key, {Value, Time}, Dict)};
store(Key, Value, empty) ->
    {cache, os:timestamp(), dict:store(Key, {Value, 0}, dict:new())}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

empty_test() ->
    ?assertEqual(empty, ?MODULE:new()),
    ?assertEqual(0, ?MODULE:size(empty)),
    ?assertEqual(not_found, ?MODULE:lookup(foo, empty)),
    ?assertMatch({[], empty}, ?MODULE:evict_older_than(empty, 10)).

nonempty_test() ->
    Cache = ?MODULE:store(foo, bar, empty),
    ?assertMatch({found, bar, _}, ?MODULE:lookup(foo, Cache)),
    ?assertMatch(not_found, ?MODULE:lookup(baz, Cache)),
    ?assertMatch({[], _}, ?MODULE:evict_older_than(Cache, 50)),
    ?assertMatch({cache, _, _}, Cache),
    ?assertEqual(1, ?MODULE:size(Cache)),
    receive after 51 -> ok end, %% expire cache
    ?assertEqual({[{foo, bar}], empty}, ?MODULE:evict_older_than(Cache, 50)),
    %% lookup un-expires cache
    {found, bar, NewCache} = ?MODULE:lookup(foo, Cache),
    ?assertMatch({[], {cache, _, _}}, ?MODULE:evict_older_than(NewCache, 50)),
    %% store also un-expires
    NewCache2 = ?MODULE:store(foo, baz, Cache),
    ?assertMatch({[], {cache, _, _}}, ?MODULE:evict_older_than(NewCache2, 50)).

-endif.
