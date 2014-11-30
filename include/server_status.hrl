%% MySQL/OTP – MySQL client library for Erlang/OTP
%% Copyright (C) 2014 Viktor Söderqvist
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
