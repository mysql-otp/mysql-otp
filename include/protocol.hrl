%% --- Status flags (bits) ---

-define(SERVER_STATUS_IN_TRANS, 16#0001).       %% a transaction is active
-define(SERVER_STATUS_AUTOCOMMIT, 16#0002).     %% auto-commit is enabled
-define(SERVER_MORE_RESULTS_EXISTS, 16#0008).
-define(SERVER_STATUS_NO_GOOD_INDEX_USED, 16#0010).
-define(SERVER_STATUS_NO_INDEX_USED, 16#0020).
-define(SERVER_STATUS_CURSOR_EXISTS, 16#0040).  %% Used by Binary Protocol
                                                %% Resultset to signal that
                                                %% COM_STMT_FETCH has to be used
                                                %% to fetch the row-data.
-define(SERVER_STATUS_LAST_ROW_SENT, 16#0080).
-define(SERVER_STATUS_DB_DROPPED, 16#0100).
-define(SERVER_STATUS_NO_BACKSLASH_ESCAPES, 16#0200).
-define(SERVER_STATUS_METADATA_CHANGED, 16#0400).
-define(SERVER_QUERY_WAS_SLOW, 16#0800).
-define(SERVER_PS_OUT_PARAMS, 16#1000).
-define(SERVER_STATUS_IN_TRANS_READONLY, 16#2000). %% in a read-only transaction
-define(SERVER_SESSION_STATE_CHANGED, 16#4000). %% connection state information
                                                %% has changed

%% Response packet tag (first byte)
-define(OK, 0).
-define(EOF, 16#fe).
-define(ERROR, 16#ff).

%% Character sets
-define(UTF8, 16#21). %% utf8_general_ci

%% --- Capability flags ---

%% Server: supports the 4.1 protocol 
%% Client: uses the 4.1 protocol 
-define(CLIENT_PROTOCOL_41, 16#00000200).

%% Server: can send status flags in EOF_Packet 
%% Client: expects status flags in EOF_Packet 
-define(CLIENT_TRANSACTIONS, 16#00002000).

%% Server: supports Authentication::Native41 
%% Client: supports Authentication::Native41 
-define(CLIENT_SECURE_CONNECTION, 16#00008000).

%% Server: can handle multiple statements per COM_QUERY and COM_STMT_PREPARE 
%% Client: may send multiple statements per COM_QUERY and COM_STMT_PREPARE 
%% Requires: CLIENT_PROTOCOL_41
-define(CLIENT_MULTI_STATEMENTS, 16#00010000).

%% Server: can send multiple resultsets for COM_QUERY 
%% Client: can handle multiple resultsets for COM_QUERY 
%% Requires: CLIENT_PROTOCOL_41
-define(CLIENT_MULTI_RESULTS, 16#00020000).

%% Server: sends extra data in Initial Handshake Packet and supports the
%%         pluggable authentication protocol.
%% Client: supports auth plugins
%% Requires: CLIENT_PROTOCOL_41
-define(CLIENT_PLUGIN_AUTH, 16#00080000).

%% --- Commands ---

-define(COM_SLEEP, 16#00).
-define(COM_QUIT, 16#01).
-define(COM_INIT_DB, 16#02).
-define(COM_QUERY, 16#03).
-define(COM_FIELD_LIST, 16#04).
-define(COM_CREATE_DB, 16#05).
-define(COM_DROP_DB, 16#06).
-define(COM_REFRESH, 16#07).
-define(COM_SHUTDOWN, 16#08).
-define(COM_STATISTICS, 16#09).
-define(COM_PROCESS_INFO, 16#0a).
-define(COM_CONNECT, 16#0b).
-define(COM_PROCESS_KILL, 16#0c).
-define(COM_DEBUG, 16#0d).
-define(COM_PING, 16#0e).
-define(COM_TIME, 16#0f).
-define(COM_DELAYED_INSERT, 16#10).
-define(COM_CHANGE_USER, 16#11).
-define(COM_BINLOG_DUMP, 16#12).
-define(COM_TABLE_DUMP, 16#13).
-define(COM_CONNECT_OUT, 16#14).
-define(COM_REGISTER_SLAVE, 16#15).
-define(COM_STMT_PREPARE, 16#16).
-define(COM_STMT_EXECUTE, 16#17).
-define(COM_STMT_SEND_LONG_DATA, 16#18).
-define(COM_STMT_CLOSE, 16#19).
-define(COM_STMT_RESET, 16#1a).
-define(COM_SET_OPTION, 16#1b).
-define(COM_STMT_FETCH, 16#1c).

%% --- Types ---

-define(TYPE_DECIMAL, 16#00).
-define(TYPE_TINY, 16#01).
-define(TYPE_SHORT, 16#02).
-define(TYPE_LONG, 16#03).
-define(TYPE_FLOAT, 16#04).
-define(TYPE_DOUBLE, 16#05).
-define(TYPE_NULL, 16#06).
-define(TYPE_TIMESTAMP, 16#07).
-define(TYPE_LONGLONG, 16#08).
-define(TYPE_INT24, 16#09).
-define(TYPE_DATE, 16#0a).
-define(TYPE_TIME, 16#0b).
-define(TYPE_DATETIME, 16#0c).
-define(TYPE_YEAR, 16#0d).
-define(TYPE_VARCHAR, 16#0f).
-define(TYPE_BIT, 16#10).
-define(TYPE_NEWDECIMAL, 16#f6).
-define(TYPE_ENUM, 16#f7).
-define(TYPE_SET, 16#f8).
-define(TYPE_TINY_BLOB, 16#f9).
-define(TYPE_MEDIUM_BLOB, 16#fa).
-define(TYPE_LONG_BLOB, 16#fb).
-define(TYPE_BLOB, 16#fc).
-define(TYPE_VAR_STRING, 16#fd).
-define(TYPE_STRING, 16#fe).
-define(TYPE_GEOMETRY, 16#ff).


