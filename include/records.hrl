%% --- Records ---

%% Returned by parse_handshake/1.
-record(handshake, {server_version :: binary(),
                    connection_id :: integer(),
                    capabilities :: integer(),
                    character_set :: integer(),
                    status :: integer(),
                    auth_plugin_data :: binary(),
                    auth_plugin_name :: binary()}).

%% Records returned by parse_response/1.
-record(ok_packet, {affected_rows :: integer(),
                    insert_id :: integer(),
                    status :: integer(),
                    warning_count :: integer(),
                    msg :: binary()}).
-record(error_packet, {code, state, msg}).
-record(eof_packet, {status, warning_count}).

