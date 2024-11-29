# Copyright (c) 2013-2016, Loïc Hoguin <essen@ninenines.eu>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

.PHONY: all app apps deps search rel relup docs install-docs check tests clean distclean help erlang-mk

ERLANG_MK_FILENAME := $(realpath $(lastword $(MAKEFILE_LIST)))
export ERLANG_MK_FILENAME

ERLANG_MK_VERSION = 2022.05.31-114-g509b15b-dirty
ERLANG_MK_WITHOUT = 

# Make 3.81 and 3.82 are deprecated.

ifeq ($(MAKELEVEL)$(MAKE_VERSION),03.81)
$(warning Please upgrade to GNU Make 4 or later: https://erlang.mk/guide/installation.html)
endif

ifeq ($(MAKELEVEL)$(MAKE_VERSION),03.82)
$(warning Please upgrade to GNU Make 4 or later: https://erlang.mk/guide/installation.html)
endif

# Core configuration.

PROJECT ?= $(notdir $(CURDIR))
PROJECT := $(strip $(PROJECT))

PROJECT_VERSION ?= rolling
PROJECT_MOD ?= $(PROJECT)_app
PROJECT_ENV ?= []

# Verbosity.

V ?= 0

verbose_0 = @
verbose_2 = set -x;
verbose = $(verbose_$(V))

ifeq ($V,3)
SHELL := $(SHELL) -x
endif

gen_verbose_0 = @echo " GEN   " $@;
gen_verbose_2 = set -x;
gen_verbose = $(gen_verbose_$(V))

gen_verbose_esc_0 = @echo " GEN   " $$@;
gen_verbose_esc_2 = set -x;
gen_verbose_esc = $(gen_verbose_esc_$(V))

# Temporary files directory.

ERLANG_MK_TMP ?= $(CURDIR)/.erlang.mk
export ERLANG_MK_TMP

# "erl" command.

ERL = erl -noinput -boot no_dot_erlang -kernel start_distribution false +P 1024 +Q 1024

# Platform detection.

ifeq ($(PLATFORM),)
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
PLATFORM = linux
else ifeq ($(UNAME_S),Darwin)
PLATFORM = darwin
else ifeq ($(UNAME_S),SunOS)
PLATFORM = solaris
else ifeq ($(UNAME_S),GNU)
PLATFORM = gnu
else ifeq ($(UNAME_S),FreeBSD)
PLATFORM = freebsd
else ifeq ($(UNAME_S),NetBSD)
PLATFORM = netbsd
else ifeq ($(UNAME_S),OpenBSD)
PLATFORM = openbsd
else ifeq ($(UNAME_S),DragonFly)
PLATFORM = dragonfly
else ifeq ($(shell uname -o),Msys)
PLATFORM = msys2
else
$(error Unable to detect platform. Please open a ticket with the output of uname -a.)
endif

export PLATFORM
endif

# Core targets.

all:: deps app rel

# Noop to avoid a Make warning when there's nothing to do.
rel::
	$(verbose) :

relup:: deps app

check:: tests

clean:: clean-crashdump

clean-crashdump:
ifneq ($(wildcard erl_crash.dump),)
	$(gen_verbose) rm -f erl_crash.dump
endif

distclean:: clean distclean-tmp

$(ERLANG_MK_TMP):
	$(verbose) mkdir -p $(ERLANG_MK_TMP)

distclean-tmp:
	$(gen_verbose) rm -rf $(ERLANG_MK_TMP)

help::
	$(verbose) printf "%s\n" \
		"erlang.mk (version $(ERLANG_MK_VERSION)) is distributed under the terms of the ISC License." \
		"Copyright (c) 2013-2016 Loïc Hoguin <essen@ninenines.eu>" \
		"" \
		"Usage: [V=1] $(MAKE) [target]..." \
		"" \
		"Core targets:" \
		"  all           Run deps, app and rel targets in that order" \
		"  app           Compile the project" \
		"  deps          Fetch dependencies (if needed) and compile them" \
		"  fetch-deps    Fetch dependencies recursively (if needed) without compiling them" \
		"  list-deps     List dependencies recursively on stdout" \
		"  search q=...  Search for a package in the built-in index" \
		"  rel           Build a release for this project, if applicable" \
		"  docs          Build the documentation for this project" \
		"  install-docs  Install the man pages for this project" \
		"  check         Compile and run all tests and analysis for this project" \
		"  tests         Run the tests for this project" \
		"  clean         Delete temporary and output files from most targets" \
		"  distclean     Delete all temporary and output files" \
		"  help          Display this help and exit" \
		"  erlang-mk     Update erlang.mk to the latest version"

# Core functions.

empty :=
space := $(empty) $(empty)
tab := $(empty)	$(empty)
comma := ,

define newline


endef

define comma_list
$(subst $(space),$(comma),$(strip $1))
endef

define escape_dquotes
$(subst ",\",$1)
endef

# Adding erlang.mk to make Erlang scripts who call init:get_plain_arguments() happy.
define erlang
$(ERL) $2 -pz $(ERLANG_MK_TMP)/rebar3/_build/prod/lib/*/ebin/ -eval "$(subst $(newline),,$(call escape_dquotes,$1))" -- erlang.mk
endef

ifeq ($(PLATFORM),msys2)
core_native_path = $(shell cygpath -m $1)
else
core_native_path = $1
endif

core_http_get = curl -Lf$(if $(filter-out 0,$V),,s)o $(call core_native_path,$1) $2

core_eq = $(and $(findstring $1,$2),$(findstring $2,$1))

# We skip files that contain spaces because they end up causing issues.
# Files that begin with a dot are already ignored by the wildcard function.
core_find = $(foreach f,$(wildcard $(1:%/=%)/*),$(if $(wildcard $f/.),$(call core_find,$f,$2),$(if $(filter $(subst *,%,$2),$f),$(if $(wildcard $f),$f))))

core_lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

core_ls = $(filter-out $1,$(shell echo $1))

# @todo Use a solution that does not require using perl.
core_relpath = $(shell perl -e 'use File::Spec; print File::Spec->abs2rel(@ARGV) . "\n"' $1 $2)

define core_render
	printf -- '$(subst $(newline),\n,$(subst %,%%,$(subst ','\'',$(subst $(tab),$(WS),$(call $1)))))\n' > $2
endef

# Automated update.

ERLANG_MK_REPO ?= https://github.com/ninenines/erlang.mk
ERLANG_MK_COMMIT ?=
ERLANG_MK_BUILD_CONFIG ?= build.config
ERLANG_MK_BUILD_DIR ?= .erlang.mk.build

erlang-mk: WITHOUT ?= $(ERLANG_MK_WITHOUT)
erlang-mk:
ifdef ERLANG_MK_COMMIT
	$(verbose) git clone $(ERLANG_MK_REPO) $(ERLANG_MK_BUILD_DIR)
	$(verbose) cd $(ERLANG_MK_BUILD_DIR) && git checkout $(ERLANG_MK_COMMIT)
else
	$(verbose) git clone --depth 1 $(ERLANG_MK_REPO) $(ERLANG_MK_BUILD_DIR)
endif
	$(verbose) if [ -f $(ERLANG_MK_BUILD_CONFIG) ]; then cp $(ERLANG_MK_BUILD_CONFIG) $(ERLANG_MK_BUILD_DIR)/build.config; fi
	$(gen_verbose) $(MAKE) --no-print-directory -C $(ERLANG_MK_BUILD_DIR) WITHOUT='$(strip $(WITHOUT))' UPGRADE=1
	$(verbose) cp $(ERLANG_MK_BUILD_DIR)/erlang.mk ./erlang.mk
	$(verbose) rm -rf $(ERLANG_MK_BUILD_DIR)
	$(verbose) rm -rf $(ERLANG_MK_TMP)

# The erlang.mk package index is bundled in the default erlang.mk build.
# Search for the string "copyright" to skip to the rest of the code.

# Copyright (c) 2015-2016, Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

# Verbosity.

proto_verbose_0 = @echo " PROTO " $(filter %.proto,$(?F));
proto_verbose = $(proto_verbose_$(V))

# Core targets.

ifneq ($(wildcard src/),)
ifneq ($(filter gpb protobuffs,$(BUILD_DEPS) $(DEPS)),)
PROTO_FILES := $(filter %.proto,$(ALL_SRC_FILES))
ERL_FILES += $(addprefix src/,$(patsubst %.proto,%_pb.erl,$(notdir $(PROTO_FILES))))

ifeq ($(PROTO_FILES),)
$(ERLANG_MK_TMP)/last-makefile-change-protobuffs:
	$(verbose) :
else
# Rebuild proto files when the Makefile changes.
# We exclude $(PROJECT).d to avoid a circular dependency.
$(ERLANG_MK_TMP)/last-makefile-change-protobuffs: $(filter-out $(PROJECT).d,$(MAKEFILE_LIST)) | $(ERLANG_MK_TMP)
	$(verbose) if test -f $@; then \
		touch $(PROTO_FILES); \
	fi
	$(verbose) touch $@

$(PROJECT).d:: $(ERLANG_MK_TMP)/last-makefile-change-protobuffs
endif

ifeq ($(filter gpb,$(BUILD_DEPS) $(DEPS)),)
define compile_proto.erl
	[begin
		protobuffs_compile:generate_source(F, [
			{output_include_dir, "./include"},
			{output_src_dir, "./src"}])
	end || F <- string:tokens("$1", " ")],
	halt().
endef
else
define compile_proto.erl
	[begin
		gpb_compile:file(F, [
			$(foreach i,$(sort $(dir $(PROTO_FILES))),{i$(comma) "$i"}$(comma))
			{include_as_lib, true},
			{module_name_suffix, "_pb"},
			{o_hrl, "./include"},
			{o_erl, "./src"},
			{use_packages, true}
		])
	end || F <- string:tokens("$1", " ")],
	halt().
endef
endif

ifneq ($(PROTO_FILES),)
$(PROJECT).d:: $(PROTO_FILES)
	$(verbose) mkdir -p ebin/ include/
	$(if $(strip $?),$(proto_verbose) $(call erlang,$(call compile_proto.erl,$?)))
endif
endif
endif

# Copyright (c) 2024, Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: beam-cache-restore-app beam-cache-restore-test clean-beam-cache distclean-beam-cache

BEAM_CACHE_DIR ?= $(ERLANG_MK_TMP)/beam-cache
PROJECT_BEAM_CACHE_DIR = $(BEAM_CACHE_DIR)/$(PROJECT)

clean:: clean-beam-cache

clean-beam-cache:
	$(verbose) rm -rf $(PROJECT_BEAM_CACHE_DIR)

distclean:: distclean-beam-cache

$(PROJECT_BEAM_CACHE_DIR):
	$(verbose) mkdir -p $(PROJECT_BEAM_CACHE_DIR)

distclean-beam-cache:
	$(gen_verbose) rm -rf $(BEAM_CACHE_DIR)

beam-cache-restore-app: | $(PROJECT_BEAM_CACHE_DIR)
	$(verbose) rm -rf $(PROJECT_BEAM_CACHE_DIR)/ebin-test
ifneq ($(wildcard ebin/),)
	$(verbose) mv ebin/ $(PROJECT_BEAM_CACHE_DIR)/ebin-test
endif
ifneq ($(wildcard $(PROJECT_BEAM_CACHE_DIR)/ebin-app),)
	$(gen_verbose) mv $(PROJECT_BEAM_CACHE_DIR)/ebin-app ebin/
else
	$(verbose) $(MAKE) --no-print-directory clean-app
endif

beam-cache-restore-test: | $(PROJECT_BEAM_CACHE_DIR)
	$(verbose) rm -rf $(PROJECT_BEAM_CACHE_DIR)/ebin-app
ifneq ($(wildcard ebin/),)
	$(verbose) mv ebin/ $(PROJECT_BEAM_CACHE_DIR)/ebin-app
endif
ifneq ($(wildcard $(PROJECT_BEAM_CACHE_DIR)/ebin-test),)
	$(gen_verbose) mv $(PROJECT_BEAM_CACHE_DIR)/ebin-test ebin/
else
	$(verbose) $(MAKE) --no-print-directory clean-app
endif

# Copyright (c) 2013-2016, Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: clean-app

# Configuration.

ERLC_OPTS ?= -Werror +debug_info +warn_export_vars +warn_shadow_vars \
	+warn_obsolete_guard # +bin_opt_info +warn_export_all +warn_missing_spec
COMPILE_FIRST ?=
COMPILE_FIRST_PATHS = $(addprefix src/,$(addsuffix .erl,$(COMPILE_FIRST)))
ERLC_EXCLUDE ?=
ERLC_EXCLUDE_PATHS = $(addprefix src/,$(addsuffix .erl,$(ERLC_EXCLUDE)))

ERLC_ASN1_OPTS ?=

ERLC_MIB_OPTS ?=
COMPILE_MIB_FIRST ?=
COMPILE_MIB_FIRST_PATHS = $(addprefix mibs/,$(addsuffix .mib,$(COMPILE_MIB_FIRST)))

# Verbosity.

app_verbose_0 = @echo " APP   " $(PROJECT);
app_verbose_2 = set -x;
app_verbose = $(app_verbose_$(V))

appsrc_verbose_0 = @echo " APP   " $(PROJECT).app.src;
appsrc_verbose_2 = set -x;
appsrc_verbose = $(appsrc_verbose_$(V))

makedep_verbose_0 = @echo " DEPEND" $(PROJECT).d;
makedep_verbose_2 = set -x;
makedep_verbose = $(makedep_verbose_$(V))

erlc_verbose_0 = @echo " ERLC  " $(filter-out $(patsubst %,%.erl,$(ERLC_EXCLUDE)),\
	$(filter %.erl %.core,$(?F)));
erlc_verbose_2 = set -x;
erlc_verbose = $(erlc_verbose_$(V))

xyrl_verbose_0 = @echo " XYRL  " $(filter %.xrl %.yrl,$(?F));
xyrl_verbose_2 = set -x;
xyrl_verbose = $(xyrl_verbose_$(V))

asn1_verbose_0 = @echo " ASN1  " $(filter %.asn1,$(?F));
asn1_verbose_2 = set -x;
asn1_verbose = $(asn1_verbose_$(V))

mib_verbose_0 = @echo " MIB   " $(filter %.bin %.mib,$(?F));
mib_verbose_2 = set -x;
mib_verbose = $(mib_verbose_$(V))

ifneq ($(wildcard src/),)

# Targets.

app:: $(if $(wildcard ebin/test),beam-cache-restore-app) deps
	$(verbose) $(MAKE) --no-print-directory $(PROJECT).d
	$(verbose) $(MAKE) --no-print-directory app-build

ifeq ($(wildcard src/$(PROJECT_MOD).erl),)
define app_file
{application, '$(PROJECT)', [
	{description, "$(PROJECT_DESCRIPTION)"},
	{vsn, "$(PROJECT_VERSION)"},$(if $(IS_DEP),
	{id$(comma)$(space)"$1"}$(comma))
	{modules, [$(call comma_list,$2)]},
	{registered, []},
	{applications, [$(call comma_list,kernel stdlib $(OTP_DEPS) $(LOCAL_DEPS) $(OPTIONAL_DEPS) $(foreach dep,$(DEPS),$(call query_name,$(dep))))]},
	{optional_applications, [$(call comma_list,$(OPTIONAL_DEPS))]},
	{env, $(subst \,\\,$(PROJECT_ENV))}$(if $(findstring {,$(PROJECT_APP_EXTRA_KEYS)),$(comma)$(newline)$(tab)$(subst \,\\,$(PROJECT_APP_EXTRA_KEYS)),)
]}.
endef
else
define app_file
{application, '$(PROJECT)', [
	{description, "$(PROJECT_DESCRIPTION)"},
	{vsn, "$(PROJECT_VERSION)"},$(if $(IS_DEP),
	{id$(comma)$(space)"$1"}$(comma))
	{modules, [$(call comma_list,$2)]},
	{registered, [$(call comma_list,$(PROJECT)_sup $(PROJECT_REGISTERED))]},
	{applications, [$(call comma_list,kernel stdlib $(OTP_DEPS) $(LOCAL_DEPS) $(OPTIONAL_DEPS) $(foreach dep,$(DEPS),$(call query_name,$(dep))))]},
	{optional_applications, [$(call comma_list,$(OPTIONAL_DEPS))]},
	{mod, {$(PROJECT_MOD), []}},
	{env, $(subst \,\\,$(PROJECT_ENV))}$(if $(findstring {,$(PROJECT_APP_EXTRA_KEYS)),$(comma)$(newline)$(tab)$(subst \,\\,$(PROJECT_APP_EXTRA_KEYS)),)
]}.
endef
endif

app-build: ebin/$(PROJECT).app
	$(verbose) :

# Source files.

ALL_SRC_FILES := $(sort $(call core_find,src/,*))

ERL_FILES := $(filter %.erl,$(ALL_SRC_FILES))
CORE_FILES := $(filter %.core,$(ALL_SRC_FILES))

# ASN.1 files.

ifneq ($(wildcard asn1/),)
ASN1_FILES = $(sort $(call core_find,asn1/,*.asn1))
ERL_FILES += $(addprefix src/,$(patsubst %.asn1,%.erl,$(notdir $(ASN1_FILES))))

define compile_asn1
	$(verbose) mkdir -p include/
	$(asn1_verbose) erlc -v -I include/ -o asn1/ +noobj $(ERLC_ASN1_OPTS) $1
	$(verbose) mv asn1/*.erl src/
	-$(verbose) mv asn1/*.hrl include/
	$(verbose) mv asn1/*.asn1db include/
endef

$(PROJECT).d:: $(ASN1_FILES)
	$(if $(strip $?),$(call compile_asn1,$?))
endif

# SNMP MIB files.

ifneq ($(wildcard mibs/),)
MIB_FILES = $(sort $(call core_find,mibs/,*.mib))

$(PROJECT).d:: $(COMPILE_MIB_FIRST_PATHS) $(MIB_FILES)
	$(verbose) mkdir -p include/ priv/mibs/
	$(mib_verbose) erlc -v $(ERLC_MIB_OPTS) -o priv/mibs/ -I priv/mibs/ $?
	$(mib_verbose) erlc -o include/ -- $(addprefix priv/mibs/,$(patsubst %.mib,%.bin,$(notdir $?)))
endif

# Leex and Yecc files.

XRL_FILES := $(filter %.xrl,$(ALL_SRC_FILES))
XRL_ERL_FILES = $(addprefix src/,$(patsubst %.xrl,%.erl,$(notdir $(XRL_FILES))))
ERL_FILES += $(XRL_ERL_FILES)

YRL_FILES := $(filter %.yrl,$(ALL_SRC_FILES))
YRL_ERL_FILES = $(addprefix src/,$(patsubst %.yrl,%.erl,$(notdir $(YRL_FILES))))
ERL_FILES += $(YRL_ERL_FILES)

$(PROJECT).d:: $(XRL_FILES) $(YRL_FILES)
	$(if $(strip $?),$(xyrl_verbose) erlc -v -o src/ $(YRL_ERLC_OPTS) $?)

# Erlang and Core Erlang files.

define makedep.erl
	E = ets:new(makedep, [bag]),
	G = digraph:new([acyclic]),
	ErlFiles = lists:usort(string:tokens("$(ERL_FILES)", " ")),
	DepsDir = "$(call core_native_path,$(DEPS_DIR))",
	AppsDir = "$(call core_native_path,$(APPS_DIR))",
	DepsDirsSrc = "$(if $(wildcard $(DEPS_DIR)/*/src), $(call core_native_path,$(wildcard $(DEPS_DIR)/*/src)))",
	DepsDirsInc = "$(if $(wildcard $(DEPS_DIR)/*/include), $(call core_native_path,$(wildcard $(DEPS_DIR)/*/include)))",
	AppsDirsSrc = "$(if $(wildcard $(APPS_DIR)/*/src), $(call core_native_path,$(wildcard $(APPS_DIR)/*/src)))",
	AppsDirsInc = "$(if $(wildcard $(APPS_DIR)/*/include), $(call core_native_path,$(wildcard $(APPS_DIR)/*/include)))",
	DepsDirs = lists:usort(string:tokens(DepsDirsSrc++DepsDirsInc, " ")),
	AppsDirs = lists:usort(string:tokens(AppsDirsSrc++AppsDirsInc, " ")),
	Modules = [{list_to_atom(filename:basename(F, ".erl")), F} || F <- ErlFiles],
	Add = fun (Mod, Dep) ->
		case lists:keyfind(Dep, 1, Modules) of
			false -> ok;
			{_, DepFile} ->
				{_, ModFile} = lists:keyfind(Mod, 1, Modules),
				ets:insert(E, {ModFile, DepFile}),
				digraph:add_vertex(G, Mod),
				digraph:add_vertex(G, Dep),
				digraph:add_edge(G, Mod, Dep)
		end
	end,
	AddHd = fun (F, Mod, DepFile) ->
		case file:open(DepFile, [read]) of
			{error, enoent} ->
				ok;
			{ok, Fd} ->
				{_, ModFile} = lists:keyfind(Mod, 1, Modules),
				case ets:match(E, {ModFile, DepFile}) of
					[] ->
						ets:insert(E, {ModFile, DepFile}),
						F(F, Fd, Mod,0);
					_ -> ok
				end
		end
	end,
	SearchHrl = fun
		F(_Hrl, []) -> {error,enoent};
		F(Hrl, [Dir|Dirs]) ->
			HrlF = filename:join([Dir,Hrl]),
			case filelib:is_file(HrlF) of
				true  ->
				{ok, HrlF};
				false -> F(Hrl,Dirs)
			end
	end,
	Attr = fun
		(_F, Mod, behavior, Dep) ->
			Add(Mod, Dep);
		(_F, Mod, behaviour, Dep) ->
			Add(Mod, Dep);
		(_F, Mod, compile, {parse_transform, Dep}) ->
			Add(Mod, Dep);
		(_F, Mod, compile, Opts) when is_list(Opts) ->
			case proplists:get_value(parse_transform, Opts) of
				undefined -> ok;
				Dep -> Add(Mod, Dep)
			end;
		(F, Mod, include, Hrl) ->
			case SearchHrl(Hrl, ["src", "include",AppsDir,DepsDir]++AppsDirs++DepsDirs) of
				{ok, FoundHrl} -> AddHd(F, Mod, FoundHrl);
				{error, _} -> false
			end;
		(F, Mod, include_lib, Hrl) ->
			case SearchHrl(Hrl, ["src", "include",AppsDir,DepsDir]++AppsDirs++DepsDirs) of
				{ok, FoundHrl} -> AddHd(F, Mod, FoundHrl);
				{error, _} -> false
			end;
		(F, Mod, import, {Imp, _}) ->
			IsFile =
				case lists:keyfind(Imp, 1, Modules) of
					false -> false;
					{_, FilePath} -> filelib:is_file(FilePath)
				end,
			case IsFile of
				false -> ok;
				true -> Add(Mod, Imp)
			end;
		(_, _, _, _) -> ok
	end,
	MakeDepend = fun
		(F, Fd, Mod, StartLocation) ->
			case io:parse_erl_form(Fd, undefined, StartLocation) of
				{ok, AbsData, EndLocation} ->
					case AbsData of
						{attribute, _, Key, Value} ->
							Attr(F, Mod, Key, Value),
							F(F, Fd, Mod, EndLocation);
						_ -> F(F, Fd, Mod, EndLocation)
					end;
				{eof, _ } -> file:close(Fd);
				{error, ErrorDescription } ->
					file:close(Fd);
				{error, ErrorInfo, ErrorLocation} ->
					F(F, Fd, Mod, ErrorLocation)
			end,
			ok
	end,
	[begin
		Mod = list_to_atom(filename:basename(F, ".erl")),
		case file:open(F, [read]) of
			{ok, Fd} -> MakeDepend(MakeDepend, Fd, Mod,0);
			{error, enoent} -> ok
		end
	end || F <- ErlFiles],
	Depend = sofs:to_external(sofs:relation_to_family(sofs:relation(ets:tab2list(E)))),
	CompileFirst = [X || X <- lists:reverse(digraph_utils:topsort(G)), [] =/= digraph:in_neighbours(G, X)],
	TargetPath = fun(Target) ->
		case lists:keyfind(Target, 1, Modules) of
			false -> "";
			{_, DepFile} ->
				DirSubname = tl(string:tokens(filename:dirname(DepFile), "/")),
				string:join(DirSubname ++ [atom_to_list(Target)], "/")
		end
	end,
	Output0 = [
		"# Generated by Erlang.mk. Edit at your own risk!\n\n",
		[[F, "::", [[" ", D] || D <- Deps], "; @touch \$$@\n"] || {F, Deps} <- Depend],
		"\nCOMPILE_FIRST +=", [[" ", TargetPath(CF)] || CF <- CompileFirst], "\n"
	],
	Output = case "é" of
		[233] -> unicode:characters_to_binary(Output0);
		_ -> Output0
	end,
	ok = file:write_file("$1", Output),
	halt()
endef

ifeq ($(if $(NO_MAKEDEP),$(wildcard $(PROJECT).d),),)
$(PROJECT).d:: $(ERL_FILES) $(call core_find,include/,*.hrl) $(MAKEFILE_LIST)
	$(makedep_verbose) $(call erlang,$(call makedep.erl,$@))
endif

ifeq ($(IS_APP)$(IS_DEP),)
ifneq ($(words $(ERL_FILES) $(CORE_FILES) $(ASN1_FILES) $(MIB_FILES) $(XRL_FILES) $(YRL_FILES)),0)
# Rebuild everything when the Makefile changes.
$(ERLANG_MK_TMP)/last-makefile-change: $(MAKEFILE_LIST) | $(ERLANG_MK_TMP)
	$(verbose) if test -f $@; then \
		touch $(ERL_FILES) $(CORE_FILES) $(ASN1_FILES) $(MIB_FILES) $(XRL_FILES) $(YRL_FILES); \
		touch -c $(PROJECT).d; \
	fi
	$(verbose) touch $@

$(ERL_FILES) $(CORE_FILES) $(ASN1_FILES) $(MIB_FILES) $(XRL_FILES) $(YRL_FILES):: $(ERLANG_MK_TMP)/last-makefile-change
ebin/$(PROJECT).app:: $(ERLANG_MK_TMP)/last-makefile-change
endif
endif

$(PROJECT).d::
	$(verbose) :

include $(wildcard $(PROJECT).d)

ebin/$(PROJECT).app:: ebin/

ebin/:
	$(verbose) mkdir -p ebin/

define compile_erl
	$(erlc_verbose) erlc -v $(if $(IS_DEP),$(filter-out -Werror,$(ERLC_OPTS)),$(ERLC_OPTS)) -o ebin/ \
		-pa ebin/ -I include/ $(filter-out $(ERLC_EXCLUDE_PATHS),$(COMPILE_FIRST_PATHS) $1)
endef

define validate_app_file
	case file:consult("ebin/$(PROJECT).app") of
		{ok, _} -> halt();
		_ -> halt(1)
	end
endef

ebin/$(PROJECT).app:: $(ERL_FILES) $(CORE_FILES) $(wildcard src/$(PROJECT).app.src)
	$(eval FILES_TO_COMPILE := $(filter-out src/$(PROJECT).app.src,$?))
	$(if $(strip $(FILES_TO_COMPILE)),$(call compile_erl,$(FILES_TO_COMPILE)))
# Older git versions do not have the --first-parent flag. Do without in that case.
	$(eval GITDESCRIBE := $(shell git describe --dirty --abbrev=7 --tags --always --first-parent 2>/dev/null \
		|| git describe --dirty --abbrev=7 --tags --always 2>/dev/null || true))
	$(eval MODULES := $(patsubst %,'%',$(sort $(notdir $(basename \
		$(filter-out $(ERLC_EXCLUDE_PATHS),$(ERL_FILES) $(CORE_FILES) $(BEAM_FILES)))))))
ifeq ($(wildcard src/$(PROJECT).app.src),)
	$(app_verbose) printf '$(subst %,%%,$(subst $(newline),\n,$(subst ','\'',$(call app_file,$(GITDESCRIBE),$(MODULES)))))' \
		> ebin/$(PROJECT).app
	$(verbose) if ! $(call erlang,$(call validate_app_file)); then \
		echo "The .app file produced is invalid. Please verify the value of PROJECT_ENV." >&2; \
		exit 1; \
	fi
else
	$(verbose) if [ -z "$$(grep -e '^[^%]*{\s*modules\s*,' src/$(PROJECT).app.src)" ]; then \
		echo "Empty modules entry not found in $(PROJECT).app.src. Please consult the erlang.mk documentation for instructions." >&2; \
		exit 1; \
	fi
	$(appsrc_verbose) cat src/$(PROJECT).app.src \
		| sed "s/{[[:space:]]*modules[[:space:]]*,[[:space:]]*\[\]}/{modules, \[$(call comma_list,$(MODULES))\]}/" \
		| sed "s/{id,[[:space:]]*\"git\"}/{id, \"$(subst /,\/,$(GITDESCRIBE))\"}/" \
		> ebin/$(PROJECT).app
endif
ifneq ($(wildcard src/$(PROJECT).appup),)
	$(verbose) cp src/$(PROJECT).appup ebin/
endif

clean:: clean-app

clean-app:
	$(gen_verbose) rm -rf $(PROJECT).d ebin/ priv/mibs/ $(XRL_ERL_FILES) $(YRL_ERL_FILES) \
		$(addprefix include/,$(patsubst %.mib,%.hrl,$(notdir $(MIB_FILES)))) \
		$(addprefix include/,$(patsubst %.asn1,%.hrl,$(notdir $(ASN1_FILES)))) \
		$(addprefix include/,$(patsubst %.asn1,%.asn1db,$(notdir $(ASN1_FILES)))) \
		$(addprefix src/,$(patsubst %.asn1,%.erl,$(notdir $(ASN1_FILES))))

endif

# Copyright (c) 2016, Loïc Hoguin <essen@ninenines.eu>
# Copyright (c) 2015, Viktor Söderqvist <viktor@zuiderkwast.se>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: docs-deps

# Configuration.

ALL_DOC_DEPS_DIRS = $(addprefix $(DEPS_DIR)/,$(DOC_DEPS))

# Targets.

$(foreach dep,$(DOC_DEPS),$(eval $(call dep_target,$(dep))))

ifneq ($(SKIP_DEPS),)
doc-deps:
else
doc-deps: $(ALL_DOC_DEPS_DIRS)
	$(verbose) set -e; for dep in $(ALL_DOC_DEPS_DIRS) ; do $(MAKE) -C $$dep IS_DEP=1; done
endif

# Copyright (c) 2015-2016, Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: test-deps test-dir test-build clean-test-dir

# Configuration.

TEST_DIR ?= $(CURDIR)/test

ALL_TEST_DEPS_DIRS = $(addprefix $(DEPS_DIR)/,$(TEST_DEPS))

TEST_ERLC_OPTS ?= +debug_info +warn_export_vars +warn_shadow_vars +warn_obsolete_guard
TEST_ERLC_OPTS += -DTEST=1

# Targets.

$(foreach dep,$(TEST_DEPS),$(eval $(call dep_target,$(dep))))

ifneq ($(SKIP_DEPS),)
test-deps:
else
test-deps: $(ALL_TEST_DEPS_DIRS)
	$(verbose) set -e; for dep in $(ALL_TEST_DEPS_DIRS) ; do \
		if [ -z "$(strip $(FULL))" ] && [ ! -L $$dep ] && [ -f $$dep/ebin/dep_built ]; then \
			:; \
		else \
			$(MAKE) -C $$dep IS_DEP=1; \
			if [ ! -L $$dep ] && [ -d $$dep/ebin ]; then touch $$dep/ebin/dep_built; fi; \
		fi \
	done
endif

ifneq ($(wildcard $(TEST_DIR)),)
test-dir: $(ERLANG_MK_TMP)/$(PROJECT).last-testdir-build
	@:

test_erlc_verbose_0 = @echo " ERLC  " $(filter-out $(patsubst %,%.erl,$(ERLC_EXCLUDE)),\
	$(filter %.erl %.core,$(notdir $(FILES_TO_COMPILE))));
test_erlc_verbose_2 = set -x;
test_erlc_verbose = $(test_erlc_verbose_$(V))

define compile_test_erl
	$(test_erlc_verbose) erlc -v $(TEST_ERLC_OPTS) -o $(TEST_DIR) \
		-pa ebin/ -I include/ $1
endef

ERL_TEST_FILES = $(call core_find,$(TEST_DIR)/,*.erl)

$(ERLANG_MK_TMP)/$(PROJECT).last-testdir-build: $(ERL_TEST_FILES) $(MAKEFILE_LIST)
# When we have to recompile files in src/ the .d file always gets rebuilt.
# Therefore we want to ignore it when rebuilding test files.
	$(eval FILES_TO_COMPILE := $(if $(filter $(filter-out $(PROJECT).d,$(MAKEFILE_LIST)),$?),$(filter $(ERL_TEST_FILES),$^),$(filter $(ERL_TEST_FILES),$?)))
	$(if $(strip $(FILES_TO_COMPILE)),$(call compile_test_erl,$(FILES_TO_COMPILE)) && touch $@)
endif

test-build:: IS_TEST=1
test-build:: ERLC_OPTS=$(TEST_ERLC_OPTS)
test-build:: $(if $(wildcard src),$(if $(wildcard ebin/test),,beam-cache-restore-test)) $(if $(IS_APP),,deps test-deps)
# We already compiled everything when IS_APP=1.
ifndef IS_APP
ifneq ($(wildcard src),)
	$(verbose) $(MAKE) --no-print-directory $(PROJECT).d ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
	$(verbose) $(MAKE) --no-print-directory app-build ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
	$(gen_verbose) touch ebin/test
endif
ifneq ($(wildcard $(TEST_DIR)),)
	$(verbose) $(MAKE) --no-print-directory test-dir ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
endif
endif

# Roughly the same as test-build, but when IS_APP=1.
# We only care about compiling the current application.
ifdef IS_APP
test-build-app:: ERLC_OPTS=$(TEST_ERLC_OPTS)
test-build-app:: deps test-deps
ifneq ($(wildcard src),)
	$(verbose) $(MAKE) --no-print-directory $(PROJECT).d ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
	$(verbose) $(MAKE) --no-print-directory app-build ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
	$(gen_verbose) touch ebin/test
endif
ifneq ($(wildcard $(TEST_DIR)),)
	$(verbose) $(MAKE) --no-print-directory test-dir ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
endif
endif

clean:: clean-test-dir

clean-test-dir:
ifneq ($(wildcard $(TEST_DIR)/*.beam),)
	$(gen_verbose) rm -f $(TEST_DIR)/*.beam $(ERLANG_MK_TMP)/$(PROJECT).last-testdir-build
endif

# Copyright (c) 2013-2016, Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: plt distclean-plt dialyze

# Configuration.

DIALYZER_PLT ?= $(CURDIR)/.$(PROJECT).plt
export DIALYZER_PLT

PLT_APPS ?=
DIALYZER_DIRS ?= --src -r $(wildcard src) $(ALL_APPS_DIRS)
DIALYZER_OPTS ?= -Werror_handling -Wunmatched_returns # -Wunderspecs
DIALYZER_PLT_OPTS ?=

# Core targets.

check:: dialyze

distclean:: distclean-plt

help::
	$(verbose) printf "%s\n" "" \
		"Dialyzer targets:" \
		"  plt         Build a PLT file for this project" \
		"  dialyze     Analyze the project using Dialyzer"

# Plugin-specific targets.

define filter_opts.erl
	Opts = init:get_plain_arguments(),
	{Filtered, _} = lists:foldl(fun
		(O,                         {Os, true}) -> {[O|Os], false};
		(O = "-D",                  {Os, _})    -> {[O|Os], true};
		(O = [\\$$-, \\$$D, _ | _], {Os, _})    -> {[O|Os], false};
		(O = "-I",                  {Os, _})    -> {[O|Os], true};
		(O = [\\$$-, \\$$I, _ | _], {Os, _})    -> {[O|Os], false};
		(O = "-pa",                 {Os, _})    -> {[O|Os], true};
		(_,                         Acc)        -> Acc
	end, {[], false}, Opts),
	io:format("~s~n", [string:join(lists:reverse(Filtered), " ")]),
	halt().
endef

# DIALYZER_PLT is a variable understood directly by Dialyzer.
#
# We append the path to erts at the end of the PLT. This works
# because the PLT file is in the external term format and the
# function binary_to_term/1 ignores any trailing data.
$(DIALYZER_PLT): deps app
	$(eval DEPS_LOG := $(shell test -f $(ERLANG_MK_TMP)/deps.log && \
		while read p; do test -d $$p/ebin && echo $$p/ebin; done <$(ERLANG_MK_TMP)/deps.log))
	$(verbose) dialyzer --build_plt $(DIALYZER_PLT_OPTS) --apps \
		erts kernel stdlib $(PLT_APPS) $(OTP_DEPS) $(LOCAL_DEPS) $(DEPS_LOG) || test $$? -eq 2
	$(verbose) $(ERL) -eval 'io:format("~n~s~n", [code:lib_dir(erts)]), halt().' >> $@

plt: $(DIALYZER_PLT)

distclean-plt:
	$(gen_verbose) rm -f $(DIALYZER_PLT)

ifneq ($(wildcard $(DIALYZER_PLT)),)
dialyze: $(if $(filter --src,$(DIALYZER_DIRS)),,deps app)
	$(verbose) if ! tail -n1 $(DIALYZER_PLT) | \
		grep -q "^`$(ERL) -eval 'io:format("~s", [code:lib_dir(erts)]), halt().'`$$"; then \
		rm $(DIALYZER_PLT); \
		$(MAKE) plt; \
	fi
else
dialyze: $(DIALYZER_PLT)
endif
	$(verbose) dialyzer `$(ERL) \
		-eval "$(subst $(newline),,$(call escape_dquotes,$(call filter_opts.erl)))" \
		-extra $(ERLC_OPTS)` $(DIALYZER_DIRS) $(DIALYZER_OPTS) $(if $(wildcard ebin/),-pa ebin/)

# Copyright (c) 2013-2016, Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: distclean-edoc edoc

# Configuration.

EDOC_OPTS ?=
EDOC_SRC_DIRS ?=
EDOC_OUTPUT ?= doc

define edoc.erl
	SrcPaths = lists:foldl(fun(P, Acc) ->
		filelib:wildcard(atom_to_list(P) ++ "/{src,c_src}")
		++ lists:filter(fun(D) ->
			filelib:is_dir(D)
		end, filelib:wildcard(atom_to_list(P) ++ "/{src,c_src}/**"))
		++ Acc
	end, [], [$(call comma_list,$(patsubst %,'%',$(call core_native_path,$(EDOC_SRC_DIRS))))]),
	DefaultOpts = [{dir, "$(EDOC_OUTPUT)"}, {source_path, SrcPaths}, {subpackages, false}],
	edoc:application($(1), ".", [$(2)] ++ DefaultOpts),
	halt(0).
endef

# Core targets.

ifneq ($(strip $(EDOC_SRC_DIRS)$(wildcard doc/overview.edoc)),)
docs:: edoc
endif

distclean:: distclean-edoc

# Plugin-specific targets.

edoc: distclean-edoc doc-deps
	$(gen_verbose) $(call erlang,$(call edoc.erl,$(PROJECT),$(EDOC_OPTS)))

distclean-edoc:
	$(gen_verbose) rm -f $(EDOC_OUTPUT)/*.css $(EDOC_OUTPUT)/*.html $(EDOC_OUTPUT)/*.png $(EDOC_OUTPUT)/edoc-info

# Copyright (c) 2015-2016, Loïc Hoguin <essen@ninenines.eu>
# Copyright (c) 2014, Enrique Fernandez <enrique.fernandez@erlang-solutions.com>
# This file is contributed to erlang.mk and subject to the terms of the ISC License.

.PHONY: eunit apps-eunit

# Configuration

EUNIT_OPTS ?=
EUNIT_ERL_OPTS ?=
EUNIT_TEST_SPEC ?= $1

# Core targets.

tests:: eunit

help::
	$(verbose) printf "%s\n" "" \
		"EUnit targets:" \
		"  eunit       Run all the EUnit tests for this project"

# Plugin-specific targets.

define eunit.erl
	$(call cover.erl)
	CoverSetup(),
	case eunit:test($(call EUNIT_TEST_SPEC,$1), [$(EUNIT_OPTS)]) of
		ok -> ok;
		error -> halt(2)
	end,
	CoverExport("$(call core_native_path,$(COVER_DATA_DIR))/eunit.coverdata"),
	halt()
endef

EUNIT_ERL_OPTS += -pa $(TEST_DIR) $(CURDIR)/ebin

ifdef t
ifeq (,$(findstring :,$(t)))
eunit: test-build cover-data-dir
	$(gen_verbose) $(call erlang,$(call eunit.erl,['$(t)']),$(EUNIT_ERL_OPTS))
else
eunit: test-build cover-data-dir
	$(gen_verbose) $(call erlang,$(call eunit.erl,fun $(t)/0),$(EUNIT_ERL_OPTS))
endif
else
EUNIT_EBIN_MODS = $(notdir $(basename $(ERL_FILES) $(BEAM_FILES)))
EUNIT_TEST_MODS = $(notdir $(basename $(call core_find,$(TEST_DIR)/,*.erl)))

EUNIT_MODS = $(foreach mod,$(EUNIT_EBIN_MODS) $(filter-out \
	$(patsubst %,%_tests,$(EUNIT_EBIN_MODS)),$(EUNIT_TEST_MODS)),'$(mod)')

eunit: test-build $(if $(IS_APP)$(ROOT_DIR),,apps-eunit) cover-data-dir
ifneq ($(wildcard src/ $(TEST_DIR)),)
	$(gen_verbose) $(call erlang,$(call eunit.erl,[$(call comma_list,$(EUNIT_MODS))]),$(EUNIT_ERL_OPTS))
endif

ifneq ($(ALL_APPS_DIRS),)
apps-eunit: test-build
	$(verbose) eunit_retcode=0 ; for app in $(ALL_APPS_DIRS); do $(MAKE) -C $$app eunit IS_APP=1; \
		[ $$? -ne 0 ] && eunit_retcode=1 ; done ; \
		exit $$eunit_retcode
endif
endif

# Copyright (c) 2015-2016, Loïc Hoguin <essen@ninenines.eu>
# Copyright (c) 2014, M Robert Martin <rob@version2beta.com>
# This file is contributed to erlang.mk and subject to the terms of the ISC License.

.PHONY: shell

# Configuration.

SHELL_ERL ?= erl
SHELL_PATHS ?= $(CURDIR)/ebin $(TEST_DIR)
SHELL_OPTS ?=

ALL_SHELL_DEPS_DIRS = $(addprefix $(DEPS_DIR)/,$(SHELL_DEPS))

# Core targets

help::
	$(verbose) printf "%s\n" "" \
		"Shell targets:" \
		"  shell       Run an erlang shell with SHELL_OPTS or reasonable default"

# Plugin-specific targets.

$(foreach dep,$(SHELL_DEPS),$(eval $(call dep_target,$(dep))))

ifneq ($(SKIP_DEPS),)
build-shell-deps:
else
build-shell-deps: $(ALL_SHELL_DEPS_DIRS)
	$(verbose) set -e; for dep in $(ALL_SHELL_DEPS_DIRS) ; do \
		if [ -z "$(strip $(FULL))" ] && [ ! -L $$dep ] && [ -f $$dep/ebin/dep_built ]; then \
			:; \
		else \
			$(MAKE) -C $$dep IS_DEP=1; \
			if [ ! -L $$dep ] && [ -d $$dep/ebin ]; then touch $$dep/ebin/dep_built; fi; \
		fi \
	done
endif

shell:: build-shell-deps
	$(gen_verbose) $(SHELL_ERL) -pa $(SHELL_PATHS) $(SHELL_OPTS)

# Copyright (c) 2016, Loïc Hoguin <essen@ninenines.eu>
# Copyright (c) 2015, Viktor Söderqvist <viktor@zuiderkwast.se>
# This file is part of erlang.mk and subject to the terms of the ISC License.

COVER_REPORT_DIR ?= cover
COVER_DATA_DIR ?= $(COVER_REPORT_DIR)

ifdef COVER
COVER_APPS ?= $(notdir $(ALL_APPS_DIRS))
COVER_DEPS ?=
COVER_EXCLUDE_MODS ?=
endif

# Code coverage for Common Test.

ifdef COVER
ifdef CT_RUN
ifneq ($(wildcard $(TEST_DIR)),)
test-build:: $(TEST_DIR)/ct.cover.spec

$(TEST_DIR)/ct.cover.spec: cover-data-dir
	$(gen_verbose) printf "%s\n" \
		"{incl_app, '$(PROJECT)', details}." \
		"{incl_dirs, '$(PROJECT)', [\"$(call core_native_path,$(CURDIR)/ebin)\" \
			$(foreach a,$(COVER_APPS),$(comma) \"$(call core_native_path,$(APPS_DIR)/$a/ebin)\") \
			$(foreach d,$(COVER_DEPS),$(comma) \"$(call core_native_path,$(DEPS_DIR)/$d/ebin)\")]}." \
		'{export,"$(call core_native_path,$(abspath $(COVER_DATA_DIR))/ct.coverdata)"}.' \
		"{excl_mods, '$(PROJECT)', [$(call comma_list,$(COVER_EXCLUDE_MODS))]}." > $@

CT_RUN += -cover $(TEST_DIR)/ct.cover.spec
endif
endif
endif

# Code coverage for other tools.

ifdef COVER
define cover.erl
	CoverSetup = fun() ->
		Dirs = ["$(call core_native_path,$(CURDIR)/ebin)"
			$(foreach a,$(COVER_APPS),$(comma) "$(call core_native_path,$(APPS_DIR)/$a/ebin)")
			$(foreach d,$(COVER_DEPS),$(comma) "$(call core_native_path,$(DEPS_DIR)/$d/ebin)")],
		Excludes = [$(call comma_list,$(foreach e,$(COVER_EXCLUDE_MODS),"$e"))],
		[case file:list_dir(Dir) of
			{error, enotdir} -> false;
			{error, _} ->	halt(2);
			{ok, Files} ->
			BeamFiles =  [filename:join(Dir, File) ||
				File <- Files,
				not lists:member(filename:basename(File, ".beam"), Excludes),
				filename:extension(File) =:= ".beam"],
			case cover:compile_beam(BeamFiles) of
				{error, _} -> halt(1);
				_ -> true
			end
		end || Dir <- Dirs]
	end,
	CoverExport = fun(Filename) -> cover:export(Filename) end,
endef
else
define cover.erl
	CoverSetup = fun() -> ok end,
	CoverExport = fun(_) -> ok end,
endef
endif

# Core targets

ifdef COVER
ifneq ($(COVER_REPORT_DIR),)
tests::
	$(verbose) $(MAKE) --no-print-directory cover-report
endif

cover-data-dir: | $(COVER_DATA_DIR)

$(COVER_DATA_DIR):
	$(verbose) mkdir -p $(COVER_DATA_DIR)
else
cover-data-dir:
endif

clean:: coverdata-clean

ifneq ($(COVER_REPORT_DIR),)
distclean:: cover-report-clean
endif

help::
	$(verbose) printf "%s\n" "" \
		"Cover targets:" \
		"  cover-report  Generate a HTML coverage report from previously collected" \
		"                cover data." \
		"  all.coverdata Merge all coverdata files into all.coverdata." \
		"" \
		"If COVER=1 is set, coverage data is generated by the targets eunit and ct. The" \
		"target tests additionally generates a HTML coverage report from the combined" \
		"coverdata files from each of these testing tools. HTML reports can be disabled" \
		"by setting COVER_REPORT_DIR to empty."

# Plugin specific targets

COVERDATA = $(filter-out $(COVER_DATA_DIR)/all.coverdata,$(wildcard $(COVER_DATA_DIR)/*.coverdata))

.PHONY: coverdata-clean
coverdata-clean:
	$(gen_verbose) rm -f $(COVER_DATA_DIR)/*.coverdata $(TEST_DIR)/ct.cover.spec

# Merge all coverdata files into one.
define cover_export.erl
	$(foreach f,$(COVERDATA),cover:import("$(f)") == ok orelse halt(1),)
	cover:export("$(COVER_DATA_DIR)/$@"), halt(0).
endef

all.coverdata: $(COVERDATA) cover-data-dir
	$(gen_verbose) $(call erlang,$(cover_export.erl))

# These are only defined if COVER_REPORT_DIR is non-empty. Set COVER_REPORT_DIR to
# empty if you want the coverdata files but not the HTML report.
ifneq ($(COVER_REPORT_DIR),)

.PHONY: cover-report-clean cover-report

cover-report-clean:
	$(gen_verbose) rm -rf $(COVER_REPORT_DIR)
ifneq ($(COVER_REPORT_DIR),$(COVER_DATA_DIR))
	$(if $(shell ls -A $(COVER_DATA_DIR)/),,$(verbose) rmdir $(COVER_DATA_DIR))
endif

ifeq ($(COVERDATA),)
cover-report:
else

# Modules which include eunit.hrl always contain one line without coverage
# because eunit defines test/0 which is never called. We compensate for this.
EUNIT_HRL_MODS = $(subst $(space),$(comma),$(shell \
	grep -H -e '^\s*-include.*include/eunit\.hrl"' src/*.erl \
	| sed "s/^src\/\(.*\)\.erl:.*/'\1'/" | uniq))

define cover_report.erl
	$(foreach f,$(COVERDATA),cover:import("$(f)") == ok orelse halt(1),)
	Ms = cover:imported_modules(),
	[cover:analyse_to_file(M, "$(COVER_REPORT_DIR)/" ++ atom_to_list(M)
		++ ".COVER.html", [html])  || M <- Ms],
	Report = [begin {ok, R} = cover:analyse(M, module), R end || M <- Ms],
	EunitHrlMods = [$(EUNIT_HRL_MODS)],
	Report1 = [{M, {Y, case lists:member(M, EunitHrlMods) of
		true -> N - 1; false -> N end}} || {M, {Y, N}} <- Report],
	TotalY = lists:sum([Y || {_, {Y, _}} <- Report1]),
	TotalN = lists:sum([N || {_, {_, N}} <- Report1]),
	Perc = fun(Y, N) -> case Y + N of 0 -> 100; S -> round(100 * Y / S) end end,
	TotalPerc = Perc(TotalY, TotalN),
	{ok, F} = file:open("$(COVER_REPORT_DIR)/index.html", [write]),
	io:format(F, "<!DOCTYPE html><html>~n"
		"<head><meta charset=\"UTF-8\">~n"
		"<title>Coverage report</title></head>~n"
		"<body>~n", []),
	io:format(F, "<h1>Coverage</h1>~n<p>Total: ~p%</p>~n", [TotalPerc]),
	io:format(F, "<table><tr><th>Module</th><th>Coverage</th></tr>~n", []),
	[io:format(F, "<tr><td><a href=\"~p.COVER.html\">~p</a></td>"
		"<td>~p%</td></tr>~n",
		[M, M, Perc(Y, N)]) || {M, {Y, N}} <- Report1],
	How = "$(subst $(space),$(comma)$(space),$(basename $(COVERDATA)))",
	Date = "$(shell date -u "+%Y-%m-%dT%H:%M:%SZ")",
	io:format(F, "</table>~n"
		"<p>Generated using ~s and erlang.mk on ~s.</p>~n"
		"</body></html>", [How, Date]),
	halt().
endef

cover-report:
	$(verbose) mkdir -p $(COVER_REPORT_DIR)
	$(gen_verbose) $(call erlang,$(cover_report.erl))

endif
endif # ifneq ($(COVER_REPORT_DIR),)
