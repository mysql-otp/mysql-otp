%% MySQL/OTP – a MySQL driver for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
%%
%% This program is free software: you can redistribute it and/or modify
%% it under the terms of the GNU General Public License as published by
%% the Free Software Foundation, either version 3 of the License, or
%% (at your option) any later version.
%%
%% This program is distributed in the hope that it will be useful,
%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
%% GNU General Public License for more details.
%%
%% You should have received a copy of the GNU General Public License
%% along with this program. If not, see <https://www.gnu.org/licenses/>.

%% @doc The MySQL binary protocol is used for prepared statements. This module
%% is used mainly from the mysql_protocol module.
-module(mysql_binary).

-export([null_bitmap_decode/3, null_bitmap_encode/2]).

%% @doc Decodes a null bitmap as stored by MySQL and returns it in a strait
%% bitstring from left to right. Returns it together with the rest of the data.
%%
%% In the MySQL null bitmap the bits are stored counting bytes from the left and
%% bits within each byte from the right. (Sort of little endian.)
-spec null_bitmap_decode(NumColumns :: integer(), BitOffset :: integer(),
                         Data :: binary()) ->
    {NullBitstring :: bitstring(), Rest :: binary()}.
null_bitmap_decode(NumColumns, Data, BitOffset) ->
    %% Binary shift right by 3 is equivallent to integer division by 8.
    BitMapLength = (NumColumns + BitOffset + 7) bsr 3,
    <<NullBitstring0:BitMapLength/binary, Rest/binary>> = Data,
    <<_:BitOffset, NullBitstring:NumColumns/bitstring, _/bitstring>> =
        << <<(reverse_byte(B))/binary>> || <<B:1/binary>> <= NullBitstring0 >>,
    {NullBitstring, Rest}.

%% @doc The reverse of null_bitmap_decode/3. The number of columns is taken to
%% be the number of bits in NullBitstring. Returns the MySQL null bitmap as a
%% binary (i.e. full bytes). BitOffset is the number of unused bits that should
%% be inserted before the other bits.
-spec null_bitmap_encode(bitstring(), integer()) -> binary().
null_bitmap_encode(NullBitstring, BitOffset) ->
    PayloadLength = bit_size(NullBitstring) + BitOffset,
    %% Round up to a multiple of 8.
    BitMapLength = (PayloadLength + 7) band bnot 7,
    PadBitsLength = BitMapLength - PayloadLength,
    PaddedBitstring = <<0:BitOffset, NullBitstring/bitstring, 0:PadBitsLength>>,
    << <<(reverse_byte(B))/binary>> || <<B:1/binary>> <= PaddedBitstring >>.

%% Reverses the bits in a byte.
reverse_byte(<<A:1, B:1, C:1, D:1, E:1, F:1, G:1, H:1>>) ->
    <<H:1, G:1, F:1, E:1, D:1, C:1, B:1, A:1>>.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

null_bitmap_test() ->
    ?assertEqual({<<0, 1:1>>, <<>>}, null_bitmap_decode(9, <<0, 4>>, 2)),
    ?assertEqual(<<0, 4>>, null_bitmap_encode(<<0, 1:1>>, 2)),
    ok.

-endif.
