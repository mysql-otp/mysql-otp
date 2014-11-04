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
%% For text protocol resultsets, rows :: [[binary() | null]].
-record(resultset, {column_definitions :: [#column_definition{}],
                    rows :: [[term()]]}).

%% Response of a successfull prepare call.
-record(prepared, {statement_id :: integer(),
                   params :: [#column_definition{}],
                   columns :: [#column_definition{}],
                   warning_count :: integer()}).
