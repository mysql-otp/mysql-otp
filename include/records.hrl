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

%% --- Records ---

%% Returned by parse_handshake/1.
-record(handshake, {server_version :: binary(),
                    connection_id :: integer(),
                    capabilities :: integer(),
                    character_set :: integer(),
                    status :: integer(),
                    auth_plugin_data :: binary(),
                    auth_plugin_name :: binary()}).

%% OK packet, commonly used in the protocol.
-record(ok, {affected_rows :: integer(),
             insert_id :: integer(),
             status :: integer(),
             warning_count :: integer(),
             msg :: binary()}).
%% Error packet, commonly used in the protocol.
-record(error, {code, state, msg}).

%% EOF packet, commonly used in the protocol.
-record(eof, {status, warning_count}).

%% Column definition, used while parsing a result set.
-record(column_definition, {name, type, charset}).

%% A resultset as received from the server using the text protocol.
%% All values are binary (SQL code) except NULL.
-record(text_resultset, {column_definitions :: [#column_definition{}],
                         rows :: [[binary() | null]]}).

%% Response of a successfull prepare call.
-record(prepared, {statement_id :: integer(),
                   params :: [#column_definition{}],
                   columns :: [#column_definition{}],
                   warning_count :: integer()}).
