# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

ERLANG_MK_VERSION = 2026.10.04-25-g841abb9-dirty
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
PROJECT_MOD ?=
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

ERL = erl -noinput -boot no_dot_erlang -kernel start_distribution false +P 1024 +Q 1024 +S 1:1

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
		"Copyright (c) Loïc Hoguin <essen@ninenines.eu>" \
		"" \
		"Usage: [V=1] $(MAKE) [target]..." \
		"" \
		"Core targets:" \
		"  all           Run deps, app and rel targets in that order" \
		"  app           Compile the project" \
		"  deps          Fetch dependencies (if needed) and compile them" \
		"  fetch-deps    Fetch dependencies recursively (if needed) without building the project" \
		"  lock          Enable the dependency lock recorded in lock.mk" \
		"  unlock        Disable the dependency lock recorded in lock.mk" \
		"  list-deps     List dependencies recursively on stdout" \
		"  tree          Print the name and version of BUILD_DEPS and DEPS" \
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

define core_relpath.erl
	Drop = fun D([A|T], [A|F]) -> D(T, F); D(T, F) -> {T, F} end,
	To0 = "$(call core_native_path,$1)",
	To = filename:split(filename:absname(To0)),
	From0 = "$(call core_native_path,$2)",
	From = filename:split(filename:absname(From0)),
	Rel = case {To, From} of
		{[H|_], [H|_]} ->
			{T1, F1} = Drop(To, From),
			case lists:duplicate(length(F1), "..") ++ T1 of
				[] -> ".";
				P -> filename:join(P)
			end;
		_ ->
			filename:absname(To0)
	end,
	io:format("~s", [Rel]),
	halt()
endef

core_relpath = $(shell $(call erlang,$(call core_relpath.erl,$1,$2)))

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

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: distclean-deps clean-tmp-deps.log

# Configuration.

ifdef OTP_DEPS
$(warning The variable OTP_DEPS is deprecated in favor of LOCAL_DEPS.)
endif

IGNORE_DEPS ?=
export IGNORE_DEPS

APPS_DIR ?= $(CURDIR)/apps
export APPS_DIR

DEPS_DIR ?= $(CURDIR)/deps
export DEPS_DIR

REBAR_DEPS_DIR = $(DEPS_DIR)
export REBAR_DEPS_DIR

# When testing Erlang.mk and updating these, make sure
# to delete test/test_rebar_git before running tests again.
REBAR3_GIT ?= https://github.com/erlang/rebar3
REBAR3_COMMIT ?= 183065cc3f7ec5a9d9d4936f7e1df6246178df40 # 3.28.0

CACHE_DEPS ?= 0

CACHE_DIR ?= $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/erlang.mk
export CACHE_DIR

HEX_CONFIG ?=

define hex_config.erl
	begin
		Config0 = hex_core:default_config(),
		Config0$(HEX_CONFIG)
	end
endef

# External "early" plugins (see core/plugins.mk for regular plugins).
# They both use the core_dep_plugin macro.

define core_dep_plugin
ifeq ($2,$(PROJECT))
-include $$(patsubst $(PROJECT)/%,%,$1)
else
-include $(DEPS_DIR)/$1

$(DEPS_DIR)/$1: $(DEPS_DIR)/$2 ;
endif
endef

DEP_EARLY_PLUGINS ?=

$(foreach p,$(DEP_EARLY_PLUGINS),\
	$(eval $(if $(findstring /,$p),\
		$(call core_dep_plugin,$p,$(firstword $(subst /, ,$p))),\
		$(call core_dep_plugin,$p/early-plugins.mk,$p))))

# Query functions.

query_fetch_method = $(if $(dep_$(1)),$(call _qfm_dep,$(word 1,$(dep_$(1)))),$(call _qfm_pkg,$1))
_qfm_dep = $(if $(dep_fetch_$(1)),$1,fail)
_qfm_pkg = $(if $(pkg_$(1)_fetch),$(pkg_$(1)_fetch),fail)

query_name = $(if $(dep_$(1)),$1,$(if $(pkg_$(1)_name),$(pkg_$(1)_name),$1))

query_repo = $(call _qr,$1,$(call query_fetch_method,$1))
_qr = $(if $(query_repo_$(2)),$(call query_repo_$(2),$1),$(call query_repo_git,$1))

query_repo_default = $(if $(dep_$(1)),$(word 2,$(dep_$(1))),$(pkg_$(1)_repo))
query_repo_git = $(patsubst git://github.com/%,https://github.com/%,$(call query_repo_default,$1))
query_repo_git-subfolder = $(call query_repo_git,$1)
query_repo_git-submodule = -
query_repo_cp = $(call query_repo_default,$1)
query_repo_ln = $(call query_repo_default,$1)
query_repo_hex = https://hex.pm/packages/$(if $(word 3,$(dep_$(1))),$(word 3,$(dep_$(1))),$1)
query_repo_fail = -

query_version = $(call _qv,$1,$(call query_fetch_method,$1))
_qv = $(if $(query_version_$(2)),$(call query_version_$(2),$1),$(call query_version_default,$1))

query_version_default = $(if $(dep_$(1)_commit),$(dep_$(1)_commit),$(if $(dep_$(1)),$(word 3,$(dep_$(1))),$(pkg_$(1)_commit)))
query_version_git = $(call query_version_default,$1)
query_version_git-subfolder = $(call query_version_default,$1)
query_version_git-submodule = -
query_version_cp = -
query_version_ln = -
query_version_hex = $(if $(dep_$(1)_commit),$(dep_$(1)_commit),$(if $(dep_$(1)),$(word 2,$(dep_$(1))),$(pkg_$(1)_commit)))
query_version_fail = -

query_extra = $(call _qe,$1,$(call query_fetch_method,$1))
_qe = $(if $(query_extra_$(2)),$(call query_extra_$(2),$1),-)

query_extra_git = -
query_extra_git-subfolder = $(if $(dep_$(1)),subfolder=$(word 4,$(dep_$(1))),-)
query_extra_git-submodule = -
query_extra_cp = -
query_extra_ln = -
query_extra_hex = $(if $(dep_$(1)),package-name=$(word 3,$(dep_$(1))),-)
query_extra_fail = -

query_absolute_path = $(addprefix $(DEPS_DIR)/,$(call query_name,$1))

# Deprecated legacy query function. Used by RabbitMQ and its third party plugins.
# Can be removed once RabbitMQ has been updated and enough time has passed.
dep_name = $(call query_name,$(1))

# Application directories.

LOCAL_DEPS_DIRS = $(foreach a,$(LOCAL_DEPS),$(if $(wildcard $(APPS_DIR)/$a),$(APPS_DIR)/$a))
# Elixir is handled specially as it must be built before all other deps
# when Mix autopatching is necessary.
ALL_DEPS_DIRS = $(addprefix $(DEPS_DIR)/,$(foreach dep,$(filter-out $(IGNORE_DEPS),$(BUILD_DEPS) $(DEPS)),$(call query_name,$(dep))))

# When we are calling an app directly we don't want to include it here
# otherwise it'll be treated both as an apps and a top-level project.
ALL_APPS_DIRS = $(if $(wildcard $(APPS_DIR)/),$(filter-out $(APPS_DIR),$(shell find $(APPS_DIR) -maxdepth 1 -type d)))
ifdef ROOT_DIR
ifndef IS_APP
ALL_APPS_DIRS := $(filter-out $(APPS_DIR)/$(notdir $(CURDIR)),$(ALL_APPS_DIRS))
endif
endif

ifeq ($(PLATFORM),msys2)
ERL_LIBS_SEP = ;
else
ERL_LIBS_SEP = :
endif

APPS_DIR_N := $(call core_native_path,$(APPS_DIR))
DEPS_DIR_N := $(call core_native_path,$(DEPS_DIR))

ifeq ($(filter $(APPS_DIR_N) $(DEPS_DIR_N),$(subst $(ERL_LIBS_SEP), ,$(ERL_LIBS))),)
ifeq ($(ERL_LIBS),)
	ERL_LIBS = $(APPS_DIR_N)$(ERL_LIBS_SEP)$(DEPS_DIR_N)
else
	ERL_LIBS := $(ERL_LIBS)$(ERL_LIBS_SEP)$(APPS_DIR_N)$(ERL_LIBS_SEP)$(DEPS_DIR_N)
endif
endif
export ERL_LIBS

export NO_AUTOPATCH

# Elixir.

# Elixir is automatically enabled in all cases except when
# an Erlang project uses an Elixir dependency. In that case
# $(ELIXIR) must be set explicitly.
ELIXIR ?= $(if $(filter elixir,$(BUILD_DEPS) $(DEPS)),dep,$(if $(EX_FILES),system,disable))
export ELIXIR

# Verbosity.

dep_verbose_0 = @echo " DEP    $1 ($(call query_version,$1))";
dep_verbose_2 = set -x;
dep_verbose = $(dep_verbose_$(V))

# Core targets.

ALL_APPS_DIRS_TO_BUILD = $(if $(LOCAL_DEPS_DIRS)$(IS_APP),$(LOCAL_DEPS_DIRS),$(ALL_APPS_DIRS))

apps:: $(ALL_APPS_DIRS) clean-tmp-deps.log | $(ERLANG_MK_TMP)
# Create ebin directory for all apps to make sure Erlang recognizes them
# as proper OTP applications when using -include_lib. This is a temporary
# fix, a proper fix would be to compile apps/* in the right order.
ifndef IS_APP
ifneq ($(ALL_APPS_DIRS),)
	$(verbose) set -e; for dep in $(ALL_APPS_DIRS) ; do \
		mkdir -p $$dep/ebin; \
	done
endif
endif
# At the toplevel: if LOCAL_DEPS is defined with at least one local app, only
# compile that list of apps. Otherwise, compile everything.
# Within an app: compile all LOCAL_DEPS that are (uncompiled) local apps.
ifneq ($(ALL_APPS_DIRS_TO_BUILD),)
	$(verbose) set -e; for dep in $(ALL_APPS_DIRS_TO_BUILD); do \
		if grep -qs ^$$dep$$ $(ERLANG_MK_TMP)/apps.log; then \
			:; \
		else \
			echo $$dep >> $(ERLANG_MK_TMP)/apps.log; \
			$(MAKE) -C $$dep $(if $(IS_TEST),test-build-app) IS_APP=1; \
		fi \
	done
endif

clean-tmp-deps.log:
ifeq ($(IS_APP)$(IS_DEP),)
	$(verbose) rm -f $(ERLANG_MK_TMP)/apps.log $(ERLANG_MK_TMP)/deps.log
endif

# Erlang.mk does not rebuild dependencies after they were compiled
# once. If a developer is working on the top-level project and some
# dependencies at the same time, he may want to change this behavior.
# There are two solutions:
#     1. Set `FULL=1` so that all dependencies are visited and
#        recursively recompiled if necessary.
#     2. Set `FORCE_REBUILD=` to the specific list of dependencies that
#        should be recompiled (instead of the whole set).

FORCE_REBUILD ?=

ifeq ($(origin FULL),undefined)
ifneq ($(strip $(force_rebuild_dep)$(FORCE_REBUILD)),)
define force_rebuild_dep
echo "$(FORCE_REBUILD)" | grep -qw "$$(basename "$1")"
endef
endif
endif

$(ERLANG_MK_TMP)/dep_built:
	$(verbose) mkdir -p $(ERLANG_MK_TMP)/dep_built

ifneq ($(SKIP_DEPS),)
deps::
else
ALL_DEPS_DIRS_TO_BUILD = $(if $(filter-out $(DEPS_DIR)/elixir,$(ALL_DEPS_DIRS)),$(filter-out $(DEPS_DIR)/elixir,$(ALL_DEPS_DIRS)),$(ALL_DEPS_DIRS))

deps:: $(ALL_DEPS_DIRS_TO_BUILD) apps clean-tmp-deps.log | $(ERLANG_MK_TMP)/dep_built
ifneq ($(ALL_DEPS_DIRS_TO_BUILD),)
	$(verbose) set -e; for dep in $(ALL_DEPS_DIRS_TO_BUILD); do \
		if grep -qs ^$$dep$$ $(ERLANG_MK_TMP)/deps.log; then \
			:; \
		else \
			echo $$dep >> $(ERLANG_MK_TMP)/deps.log; \
			if [ -z "$(strip $(FULL))" ] $(if $(force_rebuild_dep),&& ! ($(call force_rebuild_dep,$$dep)),) && [ ! -L $$dep ] && [ -f $(ERLANG_MK_TMP)/dep_built/`basename $$dep` ]; then \
				:; \
			elif [ "$$dep" = "$(DEPS_DIR)/hut" -a "$(HUT_PATCH)" ]; then \
				$(MAKE) -C $$dep app IS_DEP=1; \
				if [ ! -L $$dep ] && [ -d $$dep/ebin ]; then touch $(ERLANG_MK_TMP)/dep_built/`basename $$dep`; fi; \
			elif [ -f $$dep/GNUmakefile ] || [ -f $$dep/makefile ] || [ -f $$dep/Makefile ]; then \
				$(MAKE) -C $$dep IS_DEP=1; \
				if [ ! -L $$dep ] && [ -d $$dep/ebin ]; then touch $(ERLANG_MK_TMP)/dep_built/`basename $$dep`; fi; \
			else \
				echo "Error: No Makefile to build dependency $$dep." >&2; \
				exit 2; \
			fi \
		fi \
	done
endif
endif

# Deps related targets.

autopatch_verbose_0 = @echo " PATCH " $(subst autopatch-,,$@) "(method: $(AUTOPATCH_METHOD))";
autopatch_verbose_2 = set -x;
autopatch_verbose = $(autopatch_verbose_$(V))

define dep_autopatch_detect
	if [ -f $(DEPS_DIR)/$1/erlang.mk ]; then \
		echo erlang.mk; \
	elif [ -f $(DEPS_DIR)/$1/mix.exs -a -d $(DEPS_DIR)/$1/lib ]; then \
		if [ "$(ELIXIR)" != "disable" ]; then \
			echo mix; \
		elif [ -f $(DEPS_DIR)/$1/rebar.lock -o -f $(DEPS_DIR)/$1/rebar.config ]; then \
			echo rebar3; \
		elif [ -f $(DEPS_DIR)/$1/Makefile ]; then \
			echo noop; \
		else \
			exit 99; \
		fi \
	elif [ -f $(DEPS_DIR)/$1/Makefile ]; then \
		if [ -f $(DEPS_DIR)/$1/rebar.lock ]; then \
			echo rebar3; \
		elif [ 0 != \`grep -c "include ../\w*\.mk" $(DEPS_DIR)/$1/Makefile\` ]; then \
			echo rebar3; \
		elif [ 0 != \`grep -ci "^[^#].*rebar" $(DEPS_DIR)/$1/Makefile\` ]; then \
			echo rebar3; \
		elif [ -n "\`find $(DEPS_DIR)/$1/ -type f -name \*.mk -not -name erlang.mk -exec grep -i "^[^#].*rebar" '{}' \;\`" ]; then \
			echo rebar3; \
		else \
			echo noop; \
		fi \
	elif [ ! -d $(DEPS_DIR)/$1/src/ ]; then \
		echo noop; \
	else \
		echo rebar3; \
	fi
endef

define dep_autopatch_for_erlang.mk
	rm -rf $(DEPS_DIR)/$1/ebin; \
	$(call erlang,$(call dep_autopatch_appsrc.erl,$1)); \
	$(call dep_autopatch_erlang_mk,$1)
endef

define dep_autopatch_for_rebar3
	! test -f $(DEPS_DIR)/$1/ebin/$1.app || \
	mv -n $(DEPS_DIR)/$1/ebin/$1.app $(DEPS_DIR)/$1/src/$1.app.src; \
	rm -f $(DEPS_DIR)/$1/ebin/$1.app; \
	if [ -f $(DEPS_DIR)/$1/src/$1.app.src.script ]; then \
		$(call erlang,$(call dep_autopatch_appsrc_script.erl,$1)); \
	fi; \
	$(call erlang,$(call dep_autopatch_appsrc.erl,$1)); \
	if [ -f $(DEPS_DIR)/$1/rebar -o -f $(DEPS_DIR)/$1/rebar.config -o -f $(DEPS_DIR)/$1/rebar.config.script -o -f $(DEPS_DIR)/$1/rebar.lock ]; then \
		$(call dep_autopatch_fetch_rebar); \
		$(call dep_autopatch_rebar,$1); \
	else \
		$(call dep_autopatch_gen,$1); \
	fi
endef

define dep_autopatch_for_mix
	$(call dep_autopatch_mix,$1)
endef

define dep_autopatch_for_noop
	test -f $(DEPS_DIR)/$1/Makefile || printf "noop:\n" > $(DEPS_DIR)/$1/Makefile
endef

define maybe_flock
	if command -v flock >/dev/null; then \
		flock $1 sh -c "$2"; \
	elif command -v lockf >/dev/null; then \
		lockf -k $1 sh -c "$2"; \
	else \
		$2; \
	fi
endef

# Replace "include erlang.mk" with a line that will load the parent Erlang.mk
# if given. Do it for all 3 possible Makefile file names.
ifeq ($(NO_AUTOPATCH_ERLANG_MK),)
define dep_autopatch_erlang_mk
	for f in Makefile makefile GNUmakefile; do \
		if [ -f $(DEPS_DIR)/$1/$$f ]; then \
			sed -i.bak s/'include *erlang.mk'/'include $$(if $$(ERLANG_MK_FILENAME),$$(ERLANG_MK_FILENAME),erlang.mk)'/ $(DEPS_DIR)/$1/$$f; \
		fi \
	done
endef
else
define dep_autopatch_erlang_mk
	:
endef
endif

define dep_autopatch_gen
	printf "%s\n" \
		"ERLC_OPTS = +debug_info" \
		"include ../../erlang.mk" > $(DEPS_DIR)/$1/Makefile
endef

# We use flock/lockf when available to avoid concurrency issues.
define dep_autopatch_fetch_rebar
	$(call maybe_flock,$(ERLANG_MK_TMP)/rebar.lock,$(call dep_autopatch_fetch_rebar2))
endef

define dep_autopatch_fetch_rebar2
	if [ ! -x $(ERLANG_MK_TMP)/rebar3/rebar3 ]; then \
		rm -rf $(ERLANG_MK_TMP)/rebar3 && \
		git clone -q -n -- $(REBAR3_GIT) $(ERLANG_MK_TMP)/rebar3 && \
		cd $(ERLANG_MK_TMP)/rebar3 && \
		git checkout -q $(REBAR3_COMMIT) && \
		./bootstrap && \
		{ test -x rebar3 || cp -f _build/prod/bin/rebar3 rebar3; } && \
		cd - || { rm -rf $(ERLANG_MK_TMP)/rebar3; exit 1; }; \
	fi
endef

define dep_autopatch_rebar
	if [ -f $(DEPS_DIR)/$1/Makefile ]; then \
		mv $(DEPS_DIR)/$1/Makefile $(DEPS_DIR)/$1/Makefile.orig.mk; \
	fi; \
	$(call erlang,$(call dep_autopatch_rebar.erl,$1)); \
	rm -f $(DEPS_DIR)/$1/ebin/$1.app
endef

define dep_autopatch_rebar.erl
	application:load(rebar),
	application:set_env(rebar, log_level, debug),
	{module, rebar3} = c:l(rebar3),
	Conf1 = case file:consult("$(call core_native_path,$(DEPS_DIR)/$1/rebar.config)") of
		{ok, Conf0} -> Conf0;
		_ -> []
	end,
	{Conf, OsEnv} = fun() ->
		case filelib:is_file("$(call core_native_path,$(DEPS_DIR)/$1/rebar.config.script)") of
			false -> {Conf1, []};
			true ->
				Bindings0 = erl_eval:new_bindings(),
				Bindings1 = erl_eval:add_binding('CONFIG', Conf1, Bindings0),
				Bindings = erl_eval:add_binding('SCRIPT', "$(call core_native_path,$(DEPS_DIR)/$1/rebar.config.script)", Bindings1),
				Before = os:getenv(),
				{ok, Conf2} = file:script("$(call core_native_path,$(DEPS_DIR)/$1/rebar.config.script)", Bindings),
				{Conf2, lists:foldl(fun(E, Acc) -> lists:delete(E, Acc) end, os:getenv(), Before)}
		end
	end(),
	Write = fun (Text) ->
		file:write_file("$(call core_native_path,$(DEPS_DIR)/$1/Makefile)", Text, [append])
	end,
	Escape = fun (Text) ->
		re:replace(Text, "\\\\$$", "\$$$$", [global, {return, list}])
	end,
	Write("IGNORE_DEPS += edown eper eunit_formatters meck node_package "
		"rebar_lock_deps_plugin rebar_vsn_plugin reltool_util\n"),
	Write("C_SRC_DIR = /path/do/not/exist\n"),
	Write("C_SRC_TYPE = rebar\n"),
	Write("DRV_CFLAGS = -fPIC\nexport DRV_CFLAGS\n"),
	Write(["ERLANG_ARCH = ", rebar_utils:wordsize(), "\nexport ERLANG_ARCH\n"]),
	ToList = fun
		(V) when is_atom(V) -> atom_to_list(V);
		(V) when is_list(V) -> "'\\"" ++ V ++ "\\"'"
	end,
	fun() ->
		Write("ERLC_OPTS = +debug_info\n"),
		case lists:keyfind(erl_opts, 1, Conf) of
			false -> ok;
			{_, ErlOpts} ->
				lists:foreach(fun
					({d, D}) ->
						Write("ERLC_OPTS += -D" ++ ToList(D) ++ "=1\n");
					({d, DKey, DVal}) ->
						Write("ERLC_OPTS += -D" ++ ToList(DKey) ++ "=" ++ ToList(DVal) ++ "\n");
					({i, I}) ->
						Write(["ERLC_OPTS += -I ", I, "\n"]);
					({platform_define, Regex, D}) ->
						case rebar_utils:is_arch(Regex) of
							true -> Write("ERLC_OPTS += -D" ++ ToList(D) ++ "=1\n");
							false -> ok
						end;
					({parse_transform, PT}) ->
						Write("ERLC_OPTS += +'{parse_transform, " ++ ToList(PT) ++ "}'\n");
					(_) -> ok
				end, ErlOpts)
		end,
		Write("\n")
	end(),
	GetHexVsn2 = fun(N, NP) ->
		case file:consult("$(call core_native_path,$(DEPS_DIR)/$1/rebar.lock)") of
			{ok, Lock} ->
				LockPkgs = case lists:keyfind("1.2.0", 1, Lock) of
					{_, LP} ->
						LP;
					_ ->
						case lists:keyfind("1.1.0", 1, Lock) of
							{_, LP} ->
								LP;
							_ ->
								false
						end
				end,
				if
					is_list(LockPkgs) ->
						case lists:keyfind(atom_to_binary(N), 1, LockPkgs) of
							{_, {pkg, _, Vsn}, _} ->
								{N, {hex, NP, binary_to_list(Vsn)}};
							_ ->
								false
						end;
					true ->
						false
				end;
			_ ->
				false
		end
	end,
	ResolveHexVsn = fun(Name, Req) ->
		{ok, _} = application:ensure_all_started(ssl),
		{ok, _} = application:ensure_all_started(inets),
		Config0 = r3_hex_core:default_config(),
		Config = Config0$(HEX_CONFIG),
		Pkg = atom_to_binary(Name),
		ReqBin = list_to_binary(Req),
		maybe
			{ok, {200, _, #{releases := Releases}}} ?=
				r3_hex_repo:get_package(Config, Pkg),
			{ok, Match} ?= rebar_semver:parse_constraint(ReqBin),
			AllowPre = rebar_semver:is_prerelease_or_build(ReqBin),
			Best = lists:foldl(fun(Release, Acc) ->
				maybe
					true ?= maps:get(retired, Release, false) =:= false,
					VsnBin = maps:get(version, Release),
					true ?= AllowPre orelse
						not rebar_semver:is_prerelease_or_build(VsnBin),
					{ok, Parsed} ?= rebar_semver:parse_version(VsnBin),
					true ?= rebar_semver:match(Parsed, Match),
					true ?= case Acc of
						none -> true;
						{_, BestParsed} ->
							rebar_semver:cmp(Parsed, BestParsed) =:= gt
					end,
					{VsnBin, Parsed}
				else
					_ -> Acc
				end
			end, none, Releases),
			{VsnBin, _} ?= Best,
			binary_to_list(VsnBin)
		else
			{error, {invalid_vsn, _}} ->
				io:format(standard_error,
					"Invalid Hex requirement for ~p: ~p~n", [Name, Req]),
				halt(92);
			none ->
				io:format(standard_error,
					"No Hex release of ~p matches ~p~n", [Name, Req]),
				halt(93);
			Other ->
				io:format(standard_error,
					"Failed to get Hex package ~p: ~p~n", [Name, Other]),
				halt(94)
		end
	end,
	GetHexVsn3 = fun(N, NP, S) ->
		Req = string:trim(S),
		case rebar_semver:parse_version(list_to_binary(Req)) of
			{ok, _} ->
				{N, {hex, NP, Req}};
			{error, _} ->
				case GetHexVsn2(N, NP) of
					false ->
						{N, {hex, NP, ResolveHexVsn(NP, Req)}};
					NameSource ->
						NameSource
				end
		end
	end,
	ConvertCommit = fun
		({branch, C}) -> C;
		({ref, C}) -> C;
		({tag, C}) -> C;
		(C) -> C
	end,
	fun() ->
		File = case lists:keyfind(deps, 1, Conf) of
			false -> [];
			{_, Deps} ->
				[begin case case Dep of
							N when is_atom(N) -> GetHexVsn2(N, N);
							{N, S} when is_atom(N), is_list(S) -> GetHexVsn3(N, N, S);
							{N, {pkg, NP}} when is_atom(N) -> GetHexVsn2(N, NP);
							{N, S, {pkg, NP}} -> GetHexVsn3(N, NP, S);
							{N, S} when is_tuple(S) -> {N, S};
							{N, _, S} -> {N, S};
							{N, _, S, _} -> {N, S};
							_ -> false
						end of
					false -> ok;
					{Name, {git_subdir, Repo, Commit, SubDir}} ->
						Write(io_lib:format("DEPS += ~s\ndep_~s = git-subfolder ~s ~s ~s~n", [Name, Name, Repo, ConvertCommit(Commit), SubDir]));
					{Name, Source} ->
						{Method, Repo, Commit} = case Source of
							{hex, NPV, V} -> {hex, V, NPV};
							{git, R} -> {git, R, master};
							{M, R, C} -> {M, R, C}
						end,
						Write(io_lib:format("DEPS += ~s\ndep_~s = ~s ~s ~s~n", [Name, Name, Method, Repo, ConvertCommit(Commit)]))
				end end || Dep <- Deps]
		end
	end(),
	fun() ->
		case lists:keyfind(erl_first_files, 1, Conf) of
			false -> ok;
			{_, Files0} ->
				FixSlashes = fun(P) ->
					[if C =:= 92 -> $$/; true -> C end || C <- P]
				end,
				SrcDir = FixSlashes("$(call core_native_path,$(DEPS_DIR)/$1/src/)"),
				Files = [begin
					case filelib:wildcard(SrcDir ++ "**/" ++ filename:rootname(F) ++ ".*rl") of
						[Found|_] -> FixSlashes(Found);
						[] -> SrcDir ++ F
					end
				end || "src/" ++ F <- Files0],
				RelName = fun(Full) ->
					Rel = case lists:prefix(SrcDir, Full)
							orelse lists:prefix(string:to_lower(SrcDir), string:to_lower(Full)) of
						true -> lists:nthtail(length(SrcDir), Full);
						false -> filename:basename(Full)
					end,
					case lists:reverse(Rel) of
						"lre." ++ Elif -> lists:reverse(Elif);
						"lrx." ++ Elif -> lists:reverse(Elif);
						"lry." ++ Elif -> lists:reverse(Elif);
						Elif -> lists:reverse(Elif)
					end
				end,
				Names = [[" ", RelName(Full)] || Full <- Files],
				Write(io_lib:format("COMPILE_FIRST +=~s\n", [Names]))
		end
	end(),
	Write("\n\nrebar_dep: preprocess pre-deps deps pre-app app post-app\n"),
	Write("\npreprocess::\n"),
	Write("\npre-deps::\n"),
	Write("\npre-app::\n"),
	Write("\npost-app::\n"),
	PatchHook = fun(Cmd) ->
		Cmd2 = re:replace(Cmd, "^([g]?make)(.*)( -C.*)", "\\\\1\\\\3\\\\2", [{return, list}]),
		case Cmd2 of
			"make -C" ++ Cmd1 -> "$$\(MAKE) -C" ++ Escape(Cmd1);
			"gmake -C" ++ Cmd1 -> "$$\(MAKE) -C" ++ Escape(Cmd1);
			"make " ++ Cmd1 -> "$$\(MAKE) -f Makefile.orig.mk " ++ Escape(Cmd1);
			"gmake " ++ Cmd1 -> "$$\(MAKE) -f Makefile.orig.mk " ++ Escape(Cmd1);
			_ -> Escape(Cmd)
		end
	end,
	fun() ->
		case lists:keyfind(pre_hooks, 1, Conf) of
			false -> ok;
			{_, Hooks} ->
				[case H of
					{'get-deps', Cmd} ->
						Write("\npre-deps::\n\t" ++ PatchHook(Cmd) ++ "\n");
					{compile, Cmd} ->
						Write("\npre-app::\n\tCC=$$\(CC) " ++ PatchHook(Cmd) ++ "\n");
					{{pc, compile}, Cmd} ->
						Write("\npre-app::\n\tCC=$$\(CC) " ++ PatchHook(Cmd) ++ "\n");
					{Regex, compile, Cmd} ->
						case rebar_utils:is_arch(Regex) of
							true -> Write("\npre-app::\n\tCC=$$\(CC) " ++ PatchHook(Cmd) ++ "\n");
							false -> ok
						end;
					_ -> ok
				end || H <- Hooks]
		end
	end(),
	fun() ->
		case lists:keyfind(post_hooks, 1, Conf) of
			false -> ok;
			{_, Hooks} ->
				[case H of
					{compile, Cmd} ->
						Write("\npost-app::\n\tCC=$$\(CC) " ++ PatchHook(Cmd) ++ "\n");
					{{pc, compile}, Cmd} ->
						Write("\npost-app::\n\tCC=$$\(CC) " ++ PatchHook(Cmd) ++ "\n");
					{Regex, compile, Cmd} ->
						case rebar_utils:is_arch(Regex) of
							true -> Write("\npost-app::\n\tCC=$$\(CC) " ++ PatchHook(Cmd) ++ "\n");
							false -> ok
						end;
					_ -> ok
				end || H <- Hooks]
		end
	end(),
	ShellToMk = fun(V0) ->
		V1 = re:replace(V0, "[$$][(]", "$$\(shell ", [global]),
		V = re:replace(V1, "([$$])(?![(])(\\\\w*)", "\\\\1(\\\\2)", [global]),
		re:replace(V, "-Werror\\\\b", "", [{return, list}, global])
	end,
	PortSpecs = fun() ->
		case lists:keyfind(port_specs, 1, Conf) of
			false ->
				case filelib:is_dir("$(call core_native_path,$(DEPS_DIR)/$1/c_src)") of
					false -> [];
					true ->
						[{"priv/" ++ proplists:get_value(so_name, Conf, "$(1)_drv.so"),
							proplists:get_value(port_sources, Conf, ["c_src/*.c"]), []}]
				end;
			{_, Specs} ->
				lists:flatten([case S of
					{Output, Input} -> {ShellToMk(Output), Input, []};
					{Regex, Output, Input} ->
						case rebar_utils:is_arch(Regex) of
							true -> {ShellToMk(Output), Input, []};
							false -> []
						end;
					{Regex, Output, Input, [{env, Env}]} ->
						case rebar_utils:is_arch(Regex) of
							true -> {ShellToMk(Output), Input, Env};
							false -> []
						end
				end || S <- Specs])
		end
	end(),
	PortSpecWrite = fun (Text) ->
		file:write_file("$(call core_native_path,$(DEPS_DIR)/$1/c_src/Makefile.erlang.mk)", Text, [append])
	end,
	case PortSpecs of
		[] -> ok;
		_ ->
			Write("\npre-app::\n\t@$$\(MAKE) --no-print-directory -f c_src/Makefile.erlang.mk\n"),
			PortSpecWrite(io_lib:format("ERL_CFLAGS ?= -finline-functions -Wall -fPIC -I \\"~s/erts-~s/include\\" -I \\"~s\\"\n",
				[code:root_dir(), erlang:system_info(version), filename:join(code:lib_dir(erl_interface), "include")])),
			PortSpecWrite(io_lib:format("ERL_LDFLAGS ?= -L \\"~s\\" -lei\n",
				[filename:join(code:lib_dir(erl_interface), "lib")])),
			[PortSpecWrite(["\n", E, "\n"]) || E <- OsEnv],
			FilterEnv = fun(Env) ->
				lists:flatten([case E of
					{_, _} -> E;
					{Regex, K, V} ->
						case rebar_utils:is_arch(Regex) of
							true -> {K, V};
							false -> []
						end
				end || E <- Env])
			end,
			MergeEnv = fun(Env) ->
				lists:foldl(fun ({K, V}, Acc) ->
					case lists:keyfind(K, 1, Acc) of
						false -> [{K, rebar_utils:expand_env_variable(V, K, "")}|Acc];
						{_, V0} -> [{K, rebar_utils:expand_env_variable(V, K, V0)}|Acc]
					end
				end, [], Env)
			end,
			PortEnv = case lists:keyfind(port_env, 1, Conf) of
				false -> [];
				{_, PortEnv0} -> FilterEnv(PortEnv0)
			end,
			PortSpec = fun ({Output, Input0, Env}) ->
				filelib:ensure_dir("$(call core_native_path,$(DEPS_DIR)/$1/)" ++ Output),
				Input = [[" ", I] || I <- Input0],
				PortSpecWrite([
					[["\n", K, " = ", ShellToMk(V)] || {K, V} <- lists:reverse(MergeEnv(PortEnv))],
					case $(PLATFORM) of
						darwin -> "\n\nLDFLAGS += -flat_namespace -undefined suppress";
						_ -> ""
					end,
					"\n\nall:: ", Output, "\n\t@:\n\n",
					"%.o: %.c\n\t$$\(CC) -c -o $$\@ $$\< $$\(CFLAGS) $$\(ERL_CFLAGS) $$\(DRV_CFLAGS) $$\(EXE_CFLAGS)\n\n",
					"%.o: %.C\n\t$$\(CXX) -c -o $$\@ $$\< $$\(CXXFLAGS) $$\(ERL_CFLAGS) $$\(DRV_CFLAGS) $$\(EXE_CFLAGS)\n\n",
					"%.o: %.cc\n\t$$\(CXX) -c -o $$\@ $$\< $$\(CXXFLAGS) $$\(ERL_CFLAGS) $$\(DRV_CFLAGS) $$\(EXE_CFLAGS)\n\n",
					"%.o: %.cpp\n\t$$\(CXX) -c -o $$\@ $$\< $$\(CXXFLAGS) $$\(ERL_CFLAGS) $$\(DRV_CFLAGS) $$\(EXE_CFLAGS)\n\n",
					[[Output, ": ", K, " += ", ShellToMk(V), "\n"] || {K, V} <- lists:reverse(MergeEnv(FilterEnv(Env)))],
					Output, ": $$\(foreach ext,.c .C .cc .cpp,",
						"$$\(patsubst %$$\(ext),%.o,$$\(filter %$$\(ext),$$\(wildcard", Input, "))))\n",
					"\t$$\(CC) -o $$\@ $$\? $$\(LDFLAGS) $$\(ERL_LDFLAGS) $$\(DRV_LDFLAGS) $$\(LDLIBS) $$\(EXE_LDFLAGS)",
					case {filename:extension(Output), $(PLATFORM)} of
					    {[], _} -> "\n";
					    {".so", darwin} -> " -shared\n";
					    {".dylib", darwin} -> " -shared\n";
					    {_, darwin} -> "\n";
					    _ -> " -shared\n"
					end])
			end,
			[PortSpec(S) || S <- PortSpecs]
	end,
	fun() ->
		case lists:keyfind(plugins, 1, Conf) of
			false -> ok;
			{_, Plugins0} ->
				Plugins = [P || P <- Plugins0, is_tuple(P)],
				case lists:keyfind('lfe-compile', 1, Plugins) of
					false -> ok;
					_ -> Write("\nBUILD_DEPS = lfe lfe.mk\ndep_lfe.mk = git https://github.com/ninenines/lfe.mk master\nDEP_PLUGINS = lfe.mk\n")
				end
		end
	end(),
	Write("\ninclude $$\(if $$\(ERLANG_MK_FILENAME),$$\(ERLANG_MK_FILENAME),erlang.mk)"),
	RunPlugin = fun(Plugin, Step) ->
		case erlang:function_exported(Plugin, Step, 2) of
			false -> ok;
			true ->
				c:cd("$(call core_native_path,$(DEPS_DIR)/$1/)"),
				Ret = Plugin:Step({config, "", Conf, dict:new(), dict:new(), dict:new(),
					dict:store(base_dir, "", dict:new())}, undefined),
				io:format("rebar plugin ~p step ~p ret ~p~n", [Plugin, Step, Ret])
		end
	end,
	fun() ->
		case lists:keyfind(plugins, 1, Conf) of
			false -> ok;
			{_, Plugins0} ->
				Plugins = [P || P <- Plugins0, is_atom(P)],
				[begin
					case lists:keyfind(deps, 1, Conf) of
						false -> ok;
						{_, Deps} ->
							case lists:keyfind(P, 1, Deps) of
								false -> ok;
								_ ->
									Path = "$(call core_native_path,$(DEPS_DIR)/)" ++ atom_to_list(P),
									io:format("~s", [os:cmd("$(MAKE) -C $(call core_native_path,$(DEPS_DIR)/$1) " ++ Path)]),
									io:format("~s", [os:cmd("$(MAKE) -C " ++ Path ++ " IS_DEP=1")]),
									code:add_patha(Path ++ "/ebin")
							end
					end
				end || P <- Plugins],
				[case code:load_file(P) of
					{module, P} -> ok;
					_ ->
						case lists:keyfind(plugin_dir, 1, Conf) of
							false -> ok;
							{_, PluginsDir} ->
								ErlFile = "$(call core_native_path,$(DEPS_DIR)/$1/)" ++ PluginsDir ++ "/" ++ atom_to_list(P) ++ ".erl",
								{ok, P, Bin} = compile:file(ErlFile, [binary]),
								{module, P} = code:load_binary(P, ErlFile, Bin)
						end
				end || P <- Plugins],
				[RunPlugin(P, preprocess) || P <- Plugins],
				[RunPlugin(P, pre_compile) || P <- Plugins],
				[RunPlugin(P, compile) || P <- Plugins]
		end
	end(),
	halt()
endef

define dep_autopatch_appsrc_script.erl
	AppSrc = "$(call core_native_path,$(DEPS_DIR)/$1/src/$1.app.src)",
	AppSrcScript = AppSrc ++ ".script",
	Conf1 = case file:consult(AppSrc) of
		{ok, Conf0} -> Conf0;
		{error, enoent} -> []
	end,
	Bindings0 = erl_eval:new_bindings(),
	Bindings1 = erl_eval:add_binding('CONFIG', Conf1, Bindings0),
	Bindings = erl_eval:add_binding('SCRIPT', AppSrcScript, Bindings1),
	Conf = case file:script(AppSrcScript, Bindings) of
		{ok, [C]} -> C;
		{ok, C} -> C
	end,
	ok = file:write_file(AppSrc, io_lib:format("~p.~n", [Conf])),
	halt()
endef

define dep_autopatch_appsrc.erl
	AppSrcOut = "$(call core_native_path,$(DEPS_DIR)/$1/src/$1.app.src)",
	AppSrcIn = case filelib:is_regular(AppSrcOut) of false -> "$(call core_native_path,$(DEPS_DIR)/$1/ebin/$1.app)"; true -> AppSrcOut end,
	case filelib:is_regular(AppSrcIn) of
		false -> ok;
		true ->
			{ok, [{application, $1, L0}]} = file:consult(AppSrcIn),
			L1 = lists:keystore(modules, 1, L0, {modules, []}),
			GitDescribe = fun() -> lists:droplast(os:cmd("git -C $(DEPS_DIR)/$1 describe --dirty --tags --always")) end,
			L2 = case lists:keyfind(vsn, 1, L1) of
				{_, Vsn} when Vsn =:= git; Vsn =:= semver ->
					lists:keyreplace(vsn, 1, L1, {vsn, GitDescribe()});
				{_, {Vcs, _}} when Vcs =:= git; Vcs =:= semver ->
					lists:keyreplace(vsn, 1, L1, {vsn, GitDescribe()});
				{_, {cmd, _}} -> lists:keyreplace(vsn, 1, L1, {vsn, "cmd"});
				{_, {file, _}} -> lists:keyreplace(vsn, 1, L1, {vsn, "file"});
				_ -> L1
			end,
			L3 = case lists:keyfind(registered, 1, L2) of false -> [{registered, []}|L2]; _ -> L2 end,
			ok = file:write_file(AppSrcOut, io_lib:format("~p.~n", [{application, $1, L3}])),
			case AppSrcOut of AppSrcIn -> ok; _ -> ok = file:delete(AppSrcIn) end
	end,
	halt()
endef

define dep_lock_git
	rev=`git rev-parse HEAD` && \
	printf '%s\n' \
		'ifdef ERLANG_MK_LOCK' \
		"dep_$(call query_name,$1) := git $(call query_repo_git,$1) $$$$rev" \
		'dep_$(call query_name,$1)_commit := '"$$$$rev" \
		'endif' >> "$(ERLANG_MK_LOCK_FILE)"
endef

define dep_lock_git-subfolder
	rev=`git rev-parse HEAD` && \
	printf '%s\n' \
		'ifdef ERLANG_MK_LOCK' \
		"dep_$(call query_name,$1) := git-subfolder $(call query_repo_git-subfolder,$1) $$$$rev $(word 4,$(dep_$1))" \
		'dep_$(call query_name,$1)_commit := '"$$$$rev" \
		'endif' >> "$(ERLANG_MK_LOCK_FILE)"
endef

ifeq ($(CACHE_DEPS),1)

define dep_cache_fetch_git
	mkdir -p $(CACHE_DIR)/git; \
	if test -d "$(join $(CACHE_DIR)/git/,$(call query_name,$1))"; then \
		cd $(join $(CACHE_DIR)/git/,$(call query_name,$1)); \
		if ! git checkout -q $(call query_version,$1); then \
			git remote set-url origin $(call query_repo_git,$1) && \
			git pull --all && \
			git cat-file -e $(call query_version_git,$1) 2>/dev/null; \
		fi; \
	else \
		git clone -q -n -- $(call query_repo_git,$1) $(join $(CACHE_DIR)/git/,$(call query_name,$1)); \
	fi; \
	git clone -q --single-branch -- $(join $(CACHE_DIR)/git/,$(call query_name,$1)) $2 \
		&& cd $2 && git checkout -q $(call query_version_git,$1) \
		|| { rm -rf $2; exit 1; }
endef

define dep_fetch_git
	$(call dep_cache_fetch_git,$1,$(DEPS_DIR)/$(call query_name,$1)) && \
	$(call dep_lock_git,$1)
endef

define dep_fetch_git-subfolder
	mkdir -p $(ERLANG_MK_TMP)/git-subfolder; \
	$(call dep_cache_fetch_git,$1,$(ERLANG_MK_TMP)/git-subfolder/$(call query_name,$1)) && \
	ln -s $(ERLANG_MK_TMP)/git-subfolder/$(call query_name,$1)/$(word 4,$(dep_$1)) \
		$(DEPS_DIR)/$(call query_name,$1) && \
	$(call dep_lock_git-subfolder,$1)
endef

else

define dep_fetch_git
	git clone -q -n -- $(call query_repo_git,$1) $(DEPS_DIR)/$(call query_name,$1) \
		&& cd $(DEPS_DIR)/$(call query_name,$1) && git checkout -q $(call query_version_git,$1) && \
		$(call dep_lock_git,$1) \
		|| { rm -rf $(DEPS_DIR)/$(call query_name,$1); exit 1; }
endef

define dep_fetch_git-subfolder
	mkdir -p $(ERLANG_MK_TMP)/git-subfolder && \
	git clone -q -n -- $(call query_repo_git-subfolder,$1) \
		$(ERLANG_MK_TMP)/git-subfolder/$(call query_name,$1) && \
	cd $(ERLANG_MK_TMP)/git-subfolder/$(call query_name,$1) && \
	git checkout -q $(call query_version_git-subfolder,$1) && \
	ln -s $(ERLANG_MK_TMP)/git-subfolder/$(call query_name,$1)/$(word 4,$(dep_$1)) \
		$(DEPS_DIR)/$(call query_name,$1) && \
	$(call dep_lock_git-subfolder,$1) \
	|| { rm -rf $(ERLANG_MK_TMP)/git-subfolder/$(call query_name,$1) \
		$(DEPS_DIR)/$(call query_name,$1); exit 1; }
endef

endif

define dep_fetch_git-submodule
	git submodule update --init -- $(DEPS_DIR)/$1;
endef

define dep_fetch_cp
	cp -R $(call query_repo_cp,$1) $(DEPS_DIR)/$(call query_name,$1);
endef

define dep_fetch_ln
	ln -s $(call query_repo_ln,$1) $(DEPS_DIR)/$(call query_name,$1);
endef

NATIVE_ERLANG_MK_TMP = $(eval NATIVE_ERLANG_MK_TMP := $$(call core_native_path,$(ERLANG_MK_TMP)))$(NATIVE_ERLANG_MK_TMP)
NATIVE_CACHE_DIR = $(eval NATIVE_CACHE_DIR := $$(call core_native_path,$(CACHE_DIR)))$(NATIVE_CACHE_DIR)

define hex_get_tarball.erl
	{ok, _} = application:ensure_all_started(ssl),
	{ok, _} = application:ensure_all_started(inets),
	Config = $(hex_config.erl),
	case hex_repo:get_tarball(Config, <<"$1">>, <<"$(strip $2)">>) of
		{ok, {200, _, Tarball}} ->
			ok = file:write_file("$3", Tarball),
			halt(0);
		{ok, {Status, _, Errors}} ->
			io:format("Error ~b: ~0p~n", [Status, Errors]),
			halt(79);
		Error ->
			io:format(standard_error, "Error: ~0p~n", [Error]),
			halt(79)
	end
endef

define hex_check_tarball.erl
	case file:read_file("$4") of
		{ok, Bin} ->
			Sum = binary:encode_hex(crypto:hash(sha256, Bin), lowercase),
			Pkg = case "$3" of
				"" -> <<"$1">>;
				_ -> <<"$3">>
			end,
			IsPre = fun(V) ->
				case string:split(V, <<"-">>) of
					[_, _] -> true;
					_ -> false
				end
			end,
			Parts = fun(V) ->
				[Core | _] = string:split(V, <<"-">>),
				[binary_to_integer(N) || N <- string:split(Core, <<".">>, all)]
			end,
			Norm = fun(Ps) ->
				lists:reverse(lists:dropwhile(fun(N) -> N =:= 0 end, lists:reverse(Ps)))
			end,
			WarnNewer = fun(Releases, Using) ->
				Stable = [maps:get(version, R) || R <- Releases,
					not maps:is_key(retired, R), not IsPre(maps:get(version, R))],
				case Stable of
					[] -> ok;
					_ ->
						Latest = lists:foldl(fun(V, Best) ->
							case Norm(Parts(V)) > Norm(Parts(Best)) of
								true -> V;
								false -> Best
							end
						end, hd(Stable), tl(Stable)),
						Newer = Norm(Parts(Latest)) > Norm(Parts(Using))
							orelse (Norm(Parts(Latest)) =:= Norm(Parts(Using)) andalso IsPre(Using)),
						case Newer of
							true ->
								io:format(standard_error,
									"Warning: newer version ~s of ~s is available (using ~s).~n",
									[Latest, Pkg, Using]);
							false ->
								ok
						end
				end
			end,
			case <<"$5">> of
				<<>> ->
					{ok, _} = application:ensure_all_started(ssl),
					{ok, _} = application:ensure_all_started(inets),
					Config = $(hex_config.erl),
					LockSum = case hex_repo:get_package(Config, Pkg) of
						{ok, {200, _, #{releases := Releases}}} ->
							case [R || R <- Releases, maps:get(version, R) =:= <<"$(strip $2)">>] of
								[Release] ->
									case maps:get(outer_checksum, Release, <<>>) of
										<<>> ->
											io:format(standard_error,
												"Warning: no outer checksum for ~s ~s.~n",
												[Pkg, <<"$(strip $2)">>]),
											WarnNewer(Releases, <<"$(strip $2)">>),
											Sum;
										Outer ->
											case binary:encode_hex(Outer, lowercase) of
												Sum ->
													WarnNewer(Releases, <<"$(strip $2)">>),
													Sum;
												_ ->
													io:format(standard_error,
														"Error: checksum mismatch for ~s.~n",
														["$1"]),
													halt(101)
											end
									end;
								_ ->
									io:format(standard_error,
										"Error: no Hex release ~s ~s.~n",
										[Pkg, <<"$(strip $2)">>]),
									halt(103)
							end;
						{ok, {Status, _, Errors}} ->
							io:format(standard_error, "Error ~b: ~0p~n", [Status, Errors]),
							halt(103);
						Error ->
							io:format(standard_error, "Error: ~0p~n", [Error]),
							halt(103)
					end,
					DepLine = case "$3" of
						"" -> io_lib:format("dep_~s := hex ~s", ["$1", "$2"]);
						_ -> io_lib:format("dep_~s := hex ~s ~s", ["$1", "$2", "$3"])
					end,
					Block = iolist_to_binary([
						"ifdef ERLANG_MK_LOCK\n", DepLine, "\n",
						io_lib:format("dep_~s_commit := ~s\n", ["$1", "$2"]),
						io_lib:format("dep_~s_checksum := ~s\n", ["$1", LockSum]),
						"endif\n"
					]),
					ok = file:write_file("$6", Block, [append]),
					halt(0);
				Sum ->
					try
						true = "$7" =/= "cached",
						{ok, _} = application:ensure_all_started(ssl),
						{ok, _} = application:ensure_all_started(inets),
						Config = $(hex_config.erl),
						{ok, {200, _, #{releases := Releases}}} =
							hex_repo:get_package(Config, Pkg),
						WarnNewer(Releases, <<"$(strip $2)">>)
					catch _:_ ->
						ok
					end,
					halt(0);
				_ ->
					io:format(standard_error, "Error: checksum mismatch for ~s.~n", ["$1"]),
					halt(101)
			end;
		_ ->
			halt(102)
	end
endef

define hex_unpack_tarball.erl
	case hex_tarball:unpack({file, "$1"}, "$2") of
		{ok, _} ->
			halt(0);
		{error, Reason} ->
			io:format(standard_error, "Error: ~s~n", [hex_tarball:format_error(Reason)]),
			halt(1)
	end
endef

ifeq ($(CACHE_DEPS),1)

# Hex only has a package version. No need to look in the Erlang.mk packages.
define dep_fetch_hex
	mkdir -p $(CACHE_DIR)/hex; \
	$(eval hex_pkg_name := $(if $(word 3,$(dep_$1)),$(word 3,$(dep_$1)),$1)) \
	$(eval hex_tar_name := $(hex_pkg_name)-$(strip $(call query_version_hex,$1)).tar) \
	$(if $(wildcard $(CACHE_DIR)/hex/$(hex_tar_name)),,\
		$(call erlang,$(call hex_get_tarball.erl,$(hex_pkg_name),$(call query_version_hex,$1),$(NATIVE_CACHE_DIR)/hex/$(hex_tar_name))) &&) \
	$(call erlang,$(call hex_check_tarball.erl,$1,$(call query_version_hex,$1),$(word 3,$(dep_$1)),$(NATIVE_CACHE_DIR)/hex/$(hex_tar_name),$(dep_$1_checksum),$(call core_native_path,$(ERLANG_MK_LOCK_FILE)),$(if $(wildcard $(CACHE_DIR)/hex/$(hex_tar_name)),cached))) && \
	{ mkdir -p $(DEPS_DIR)/$1 && \
		$(call erlang,$(call hex_unpack_tarball.erl,$(NATIVE_CACHE_DIR)/hex/$(hex_tar_name),$(call core_native_path,$(DEPS_DIR)/$1))) && \
		find $(DEPS_DIR)/$1 \( -type f -o -type d \) -exec chmod go-w {} + \
		|| { rm -rf $(DEPS_DIR)/$1; exit 1; }; }
endef

else

# Hex only has a package version. No need to look in the Erlang.mk packages.
define dep_fetch_hex
	mkdir -p $(ERLANG_MK_TMP)/hex; \
	$(eval hex_pkg_name := $(if $(word 3,$(dep_$1)),$(word 3,$(dep_$1)),$1)) \
	$(call erlang,$(call hex_get_tarball.erl,$(hex_pkg_name),$(call query_version_hex,$1),$(NATIVE_ERLANG_MK_TMP)/hex/$1.tar)) && \
	$(call erlang,$(call hex_check_tarball.erl,$1,$(call query_version_hex,$1),$(word 3,$(dep_$1)),$(NATIVE_ERLANG_MK_TMP)/hex/$1.tar,$(dep_$1_checksum),$(call core_native_path,$(ERLANG_MK_LOCK_FILE)))) && \
	{ mkdir -p $(DEPS_DIR)/$1 && \
		$(call erlang,$(call hex_unpack_tarball.erl,$(NATIVE_ERLANG_MK_TMP)/hex/$1.tar,$(call core_native_path,$(DEPS_DIR)/$1))) && \
		find $(DEPS_DIR)/$1 \( -type f -o -type d \) -exec chmod go-w {} + \
		|| { rm -rf $(DEPS_DIR)/$1; exit 1; }; }
endef

endif

define dep_fetch_fail
	echo "Error: Unknown or invalid dependency: $1." >&2; \
	exit 78;
endef

define dep_target
$(DEPS_DIR)/$(call query_name,$1): $(if $(filter elixir,$(BUILD_DEPS) $(DEPS)),$(if $(filter-out elixir,$1),$(ERLANG_MK_TMP)/dep_built/elixir)) $(if $(filter hex,$(call query_fetch_method,$1)),$(if $(wildcard $(DEPS_DIR)/$(call query_name,$1)),,$(ERLANG_MK_TMP)/dep_built/hex_core)) | $(ERLANG_MK_TMP)
	$(eval DEP_NAME := $(call query_name,$1))
	$(eval DEP_STR := $(if $(filter $1,$(DEP_NAME)),$1,"$1 ($(DEP_NAME))"))
	$(verbose) rm -f $(ERLANG_MK_TMP)/dep_built/$(DEP_NAME)
	$(verbose) if test -d $(APPS_DIR)/$(DEP_NAME); then \
		echo "Error: Dependency" $(DEP_STR) "conflicts with application found in $(APPS_DIR)/$(DEP_NAME)." >&2; \
		exit 17; \
	fi
	$(verbose) mkdir -p $(DEPS_DIR)
	$(dep_verbose) $(call dep_fetch_$(strip $(call query_fetch_method,$1)),$1)
	$(verbose) if [ -f $(DEPS_DIR)/$1/configure.ac -o -f $(DEPS_DIR)/$1/configure.in ] \
			&& [ ! -f $(DEPS_DIR)/$1/configure ]; then \
		echo " AUTO  " $(DEP_STR); \
		cd $(DEPS_DIR)/$1 && autoreconf -Wall -vif -I m4; \
	fi
	- $(verbose) if [ -f $(DEPS_DIR)/$(DEP_NAME)/configure ]; then \
		echo " CONF  " $(DEP_STR); \
		cd $(DEPS_DIR)/$(DEP_NAME) && ./configure; \
	fi
ifeq ($(filter $1,$(NO_AUTOPATCH)),)
	$(verbose) AUTOPATCH_METHOD=`$(call dep_autopatch_detect,$1)`; \
	if [ $$$$? -eq 99 ]; then \
		echo "Elixir is currently disabled. Please set 'ELIXIR = system' in the Makefile to enable"; \
		exit 99; \
	fi; \
	$$(MAKE) --no-print-directory autopatch-$(DEP_NAME) AUTOPATCH_METHOD=$$$$AUTOPATCH_METHOD
endif

.PHONY: autopatch-$(call query_name,$1)

ifeq ($1,elixir)
autopatch-elixir::
	$$(verbose) mkdir -p $(DEPS_DIR)/elixir/lib/elixir/ebin
	$$(verbose) ln -s lib/elixir/ebin $(DEPS_DIR)/elixir/
else
autopatch-$(call query_name,$1)::
	$$(autopatch_verbose) $$(call dep_autopatch_for_$(AUTOPATCH_METHOD),$(call query_name,$1))
endif
endef

ifeq ($(origin ERLANG_MK_LOCK_FILE),undefined)
ERLANG_MK_LOCK_FILE := $(CURDIR)/lock.mk
endif
export ERLANG_MK_LOCK_FILE

-include $(ERLANG_MK_LOCK_FILE)

ifeq ($(IS_APP)$(IS_DEP),)

.PHONY: lock unlock

lock: fetch-deps
	$(verbose) if [ ! -f "$(ERLANG_MK_LOCK_FILE)" ]; then \
		echo "Error: lock.mk was not found. Fetch dependencies before locking." >&2; \
		exit 97; \
	fi
	$(verbose) grep -qx 'ERLANG_MK_LOCK := 1' "$(ERLANG_MK_LOCK_FILE)" || { \
		printf '%s\n\n' 'ERLANG_MK_LOCK := 1' | cat - "$(ERLANG_MK_LOCK_FILE)" > "$(ERLANG_MK_LOCK_FILE).tmp" && mv "$(ERLANG_MK_LOCK_FILE).tmp" "$(ERLANG_MK_LOCK_FILE)"; \
	}

unlock:
	$(verbose) if [ -f "$(ERLANG_MK_LOCK_FILE)" ]; then \
		grep -vx 'ERLANG_MK_LOCK := 1' "$(ERLANG_MK_LOCK_FILE)" | sed '1{/^$$/d;}' > "$(ERLANG_MK_LOCK_FILE).tmp" && mv "$(ERLANG_MK_LOCK_FILE).tmp" "$(ERLANG_MK_LOCK_FILE)"; \
	fi
endif

# We automatically depend on hex_core when the project isn't already.
$(if $(filter hex_core,$(DEPS) $(BUILD_DEPS) $(DOC_DEPS) $(REL_DEPS) $(TEST_DEPS)),,\
	$(eval $(call dep_target,hex_core)))

$(ERLANG_MK_TMP)/dep_built/hex_core: | $(ERLANG_MK_TMP)
	$(verbose) $(call maybe_flock,$(ERLANG_MK_TMP)/hex_core.lock,\
		if [ ! -e $(ERLANG_MK_TMP)/dep_built/hex_core ]; then \
			$(MAKE) $(DEPS_DIR)/hex_core; \
			$(MAKE) -C $(DEPS_DIR)/hex_core IS_DEP=1; \
			mkdir -p $(ERLANG_MK_TMP)/dep_built; \
			touch $(ERLANG_MK_TMP)/dep_built/hex_core; \
		fi)

$(ERLANG_MK_TMP)/dep_built/elixir: | $(ERLANG_MK_TMP)
	$(verbose) $(call maybe_flock,$(ERLANG_MK_TMP)/elixir.lock,\
		if [ ! -e $(ERLANG_MK_TMP)/dep_built/elixir ]; then \
			$(MAKE) $(DEPS_DIR)/elixir; \
			$(MAKE) -C $(DEPS_DIR)/elixir; \
			mkdir -p $(ERLANG_MK_TMP)/dep_built; \
			touch $(ERLANG_MK_TMP)/dep_built/elixir; \
		fi)

$(foreach dep,$(BUILD_DEPS) $(DEPS),$(eval $(call dep_target,$(dep))))

ifndef IS_APP
clean:: clean-apps

clean-apps:
	$(verbose) set -e; for dep in $(ALL_APPS_DIRS) ; do \
		$(MAKE) -C $$dep clean IS_APP=1; \
	done

distclean:: distclean-apps

distclean-apps:
	$(verbose) set -e; for dep in $(ALL_APPS_DIRS) ; do \
		$(MAKE) -C $$dep distclean IS_APP=1; \
	done
endif

ifndef SKIP_DEPS
distclean:: distclean-deps

distclean-deps:
	$(gen_verbose) rm -rf $(DEPS_DIR)
endif

ifeq ($(CACHE_DEPS),1)
cacheclean:: cacheclean-git cacheclean-hex

cacheclean-git:
	$(gen_verbose) rm -rf $(CACHE_DIR)/git

cacheclean-hex:
	$(gen_verbose) rm -rf $(CACHE_DIR)/hex
endif

# Forward-declare variables used in core/deps-tools.mk. This is required
# in case plugins use them.

ERLANG_MK_RECURSIVE_DEPS_LIST = $(ERLANG_MK_TMP)/recursive-deps-list.log
ERLANG_MK_RECURSIVE_DOC_DEPS_LIST = $(ERLANG_MK_TMP)/recursive-doc-deps-list.log
ERLANG_MK_RECURSIVE_REL_DEPS_LIST = $(ERLANG_MK_TMP)/recursive-rel-deps-list.log
ERLANG_MK_RECURSIVE_TEST_DEPS_LIST = $(ERLANG_MK_TMP)/recursive-test-deps-list.log
ERLANG_MK_RECURSIVE_SHELL_DEPS_LIST = $(ERLANG_MK_TMP)/recursive-shell-deps-list.log

ERLANG_MK_QUERY_DEPS_FILE = $(ERLANG_MK_TMP)/query-deps.log
ERLANG_MK_QUERY_DOC_DEPS_FILE = $(ERLANG_MK_TMP)/query-doc-deps.log
ERLANG_MK_QUERY_REL_DEPS_FILE = $(ERLANG_MK_TMP)/query-rel-deps.log
ERLANG_MK_QUERY_TEST_DEPS_FILE = $(ERLANG_MK_TMP)/query-test-deps.log
ERLANG_MK_QUERY_SHELL_DEPS_FILE = $(ERLANG_MK_TMP)/query-shell-deps.log

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

# Verbosity.

proto_verbose_0 = @echo " PROTO " $(filter %.proto,$(?F));
proto_verbose_all_0 = @echo " PROTO " $(notdir $(PROTO_FILES));
proto_verbose = $(proto_verbose_$(V))
proto_verbose_all = $(proto_verbose_all_$(V))

# Core targets.

ifneq ($(wildcard src/),)
ifneq ($(filter gpb protobuffs,$(BUILD_DEPS) $(DEPS)),)
PROTO_FILES := $(filter %.proto,$(ALL_SRC_FILES))
ERL_FILES += $(addprefix src/,$(patsubst %.proto,%_pb.erl,$(notdir $(PROTO_FILES))))

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
$(PROJECT).d:: $(PROTO_FILES) $(MAKEFILE_CHANGE)
	$(verbose) mkdir -p ebin/ include/
	$(if $(filter $(MAKEFILE_CHANGE),$?),\
		$(proto_verbose_all) $(call erlang,$(call compile_proto.erl,$(PROTO_FILES))),\
		$(if $(strip $(filter %.proto,$?)),$(proto_verbose) $(call erlang,$(call compile_proto.erl,$(filter %.proto,$?)))))
endif
endif
endif

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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
	$(verbose) rm $(ERLANG_MK_TMP)/$(PROJECT).test

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

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
# This file is part of erlang.mk and subject to the terms of the ISC License.

.PHONY: clean-app

# Configuration.

ERLC_OPTS ?= -Werror +debug_info +warn_export_vars +warn_shadow_vars \
	+warn_obsolete_guard # +bin_opt_info +warn_export_all +warn_missing_spec
COMPILE_FIRST ?=
COMPILE_FIRST_PATHS = $(addprefix src/,$(addsuffix .erl,$(COMPILE_FIRST)))
ERLC_EXCLUDE ?=
ERLC_EXCLUDE_PATHS = $(addprefix src/,$(addsuffix .erl,$(ERLC_EXCLUDE)))

# One Make target per Erlang source when set to 1. Any other value
# keeps a single erlc invocation. Set before including erlang.mk.
ERLC_PER_FILE ?=

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

erlc_verbose_per_file_0 = @echo " ERLC  " $(notdir $<);
erlc_verbose_per_file_2 = set -x;
erlc_verbose_per_file = $(erlc_verbose_per_file_$(V))

xyrl_verbose_0 = @echo " XYRL  " $(filter %.xrl %.yrl,$(?F));
xyrl_verbose_all_0 = @echo " XYRL  " $(notdir $(XRL_FILES) $(YRL_FILES));
xyrl_verbose_2 = set -x;
xyrl_verbose = $(xyrl_verbose_$(V))
xyrl_verbose_all = $(xyrl_verbose_all_$(V))

asn1_verbose_0 = @echo " ASN1  " $(notdir $1);
asn1_verbose_2 = set -x;
asn1_verbose = $(asn1_verbose_$(V))

mib_verbose_0 = @echo " MIB   " $(filter %.bin %.mib,$(?F));
mib_verbose_all_0 = @echo " MIB   " $(notdir $(MIB_FILES));
mib_verbose_2 = set -x;
mib_verbose = $(mib_verbose_$(V))
mib_verbose_all = $(mib_verbose_all_$(V))

ifneq ($(wildcard src/)$(wildcard lib/),)

# Targets.

app:: $(if $(wildcard $(ERLANG_MK_TMP)/$(PROJECT).test),beam-cache-restore-app) deps
	$(verbose) $(MAKE) --no-print-directory $(PROJECT).d
	$(verbose) $(MAKE) --no-print-directory app-build

PROJECT_MOD := $(if $(PROJECT_MOD),$(PROJECT_MOD),$(if $(wildcard src/$(PROJECT)_app.erl),$(PROJECT)_app))

define app_file
{application, '$(PROJECT)', [
	{description, "$(PROJECT_DESCRIPTION)"},
	{vsn, "$(PROJECT_VERSION)"},$(if $(IS_DEP),
	{id$(comma)$(space)"$1"}$(comma))
	{modules, [$(call comma_list,$2)]},
	{registered, [$(if $(PROJECT_MOD),$(call comma_list,$(if $(filter $(PROJECT_MOD),$(PROJECT)_app),$(PROJECT)_sup) $(PROJECT_REGISTERED)))]},
	{applications, [$(call comma_list,kernel stdlib $(OTP_DEPS) $(LOCAL_DEPS) $(OPTIONAL_DEPS) $(foreach dep,$(DEPS),$(call query_name,$(dep))))]},
	{optional_applications, [$(call comma_list,$(OPTIONAL_DEPS))]},$(if $(PROJECT_MOD),
	{mod$(comma)$(space){$(patsubst %,'%',$(PROJECT_MOD))$(comma)$(space)[]}}$(comma))
	{env, $(subst \,\\,$(PROJECT_ENV))}$(if $(findstring {,$(PROJECT_APP_EXTRA_KEYS)),$(comma)$(newline)$(tab)$(subst \,\\,$(PROJECT_APP_EXTRA_KEYS)),)
]}.
endef

app-build: ebin/$(PROJECT).app
	$(verbose) :

# Source files.

ALL_SRC_FILES := $(sort $(call core_find,src/,*))

ERL_FILES := $(filter %.erl,$(ALL_SRC_FILES))
CORE_FILES := $(filter %.core,$(ALL_SRC_FILES))

ALL_LIB_FILES := $(sort $(call core_find,lib/,*))
EX_FILES := $(filter-out lib/mix/%,$(filter %.ex,$(ALL_SRC_FILES) $(ALL_LIB_FILES)))
HEEX_FILES := $(filter-out lib/mix/%,$(filter %.heex,$(ALL_SRC_FILES) $(ALL_LIB_FILES)))

# Top-level projects rebuild generated files when a Makefile changes.
# Dependencies and applications under apps/ do not.
ifeq ($(IS_APP)$(IS_DEP),)
MAKEFILE_CHANGE = $(ERLANG_MK_TMP)/last-makefile-change
else
MAKEFILE_CHANGE =
endif

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

$(PROJECT).d:: $(ASN1_FILES) $(MAKEFILE_CHANGE)
	$(if $(filter $(MAKEFILE_CHANGE),$?),$(if $(strip $(ASN1_FILES)),$(call compile_asn1,$(ASN1_FILES))),$(if $(strip $(filter %.asn1,$?)),$(call compile_asn1,$(filter %.asn1,$?))))
endif

# SNMP MIB files.

ifneq ($(wildcard mibs/),)
MIB_FILES = $(sort $(call core_find,mibs/,*.mib))

define compile_mib
	$(1) erlc -v $(ERLC_MIB_OPTS) -o priv/mibs/ -I priv/mibs/ $(2)
	$(1) erlc -o include/ -- $(addprefix priv/mibs/,$(patsubst %.mib,%.bin,$(notdir $(2))))
endef

$(PROJECT).d:: $(COMPILE_MIB_FIRST_PATHS) $(MIB_FILES) $(MAKEFILE_CHANGE)
	$(verbose) mkdir -p include/ priv/mibs/
	$(if $(filter $(MAKEFILE_CHANGE),$?),\
		$(if $(strip $(COMPILE_MIB_FIRST_PATHS) $(MIB_FILES)),\
			$(call compile_mib,$(mib_verbose_all),$(COMPILE_MIB_FIRST_PATHS) $(filter-out $(COMPILE_MIB_FIRST_PATHS),$(MIB_FILES)))),\
		$(if $(strip $(filter %.mib,$?)),\
			$(call compile_mib,$(mib_verbose),$(filter %.mib,$?))))
endif

# Leex and Yecc files.

XRL_FILES := $(filter %.xrl,$(ALL_SRC_FILES))
XRL_ERL_FILES = $(addprefix src/,$(patsubst %.xrl,%.erl,$(notdir $(XRL_FILES))))
ERL_FILES += $(XRL_ERL_FILES)

YRL_FILES := $(filter %.yrl,$(ALL_SRC_FILES))
YRL_ERL_FILES = $(addprefix src/,$(patsubst %.yrl,%.erl,$(notdir $(YRL_FILES))))
ERL_FILES += $(YRL_ERL_FILES)

$(PROJECT).d:: $(XRL_FILES) $(YRL_FILES) $(MAKEFILE_CHANGE)
	$(if $(filter $(MAKEFILE_CHANGE),$?),$(if $(strip $(XRL_FILES) $(YRL_FILES)),$(xyrl_verbose_all) erlc -v -o src/ $(YRL_ERLC_OPTS) $(XRL_FILES) $(YRL_FILES)),$(if $(strip $(filter %.xrl %.yrl,$?)),$(xyrl_verbose) erlc -v -o src/ $(YRL_ERLC_OPTS) $(filter %.xrl %.yrl,$?)))

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
	Exclude = lists:usort(string:tokens("$(ERLC_EXCLUDE_PATHS)", " ")),
	PerFile = "$(ERLC_PER_FILE)" =:= "1",
	Beam = fun(File) ->
		"ebin/" ++ filename:basename(File, ".erl") ++ ".beam"
	end,
	Prereq = fun(Dep) ->
		case lists:member(Dep, Exclude) of
			true -> Dep;
			false ->
				case lists:keyfind(Dep, 2, Modules) of
					false -> Dep;
					_ -> Beam(Dep)
				end
		end
	end,
	Outside = lists:usort([D || {_, Deps} <- Depend, D <- Deps,
		not lists:prefix("include/", D), not lists:suffix(".erl", D)]),
	Output0 = [
		"# Generated by Erlang.mk. Edit at your own risk!\n\n",
		case PerFile of
			false ->
				[[[F, "::", [[" ", D] || D <- Deps], "; @touch \$$@\n"] || {F, Deps} <- Depend],
				"\nCOMPILE_FIRST +=", [[" ", TargetPath(CF)] || CF <- CompileFirst], "\n"];
			true ->
				["ERLC_OUTSIDE_HRL =", [[" ", D] || D <- Outside], "\n",
				[[Beam(F), ":", [[" ", Prereq(D)] || D <- Deps], "\n"] || {F, Deps} <- Depend]]
		end
	],
	Output = case file:native_name_encoding() of
		utf8 -> unicode:characters_to_binary(Output0);
		latin1 -> Output0
	end,
	ok = file:write_file("$1", Output),
	halt()
endef

include $(wildcard $(PROJECT).d)

ifeq ($(if $(NO_MAKEDEP),$(wildcard $(PROJECT).d),),)
$(PROJECT).d:: $(ERL_FILES) $(EX_FILES) $(call core_find,include/,*.hrl) $(ERLC_OUTSIDE_HRL) $(filter-out $(PROJECT).d,$(MAKEFILE_LIST))
# Rebuild everything when the .d file does not exist.
# We touch $@ to make sure the command doesn't fail in empty projects.
# The file will be generated with content immediately after.
	$(verbose) if ! test -e $@; then \
		touch $@ $(ERL_FILES) $(CORE_FILES) $(ASN1_FILES) $(MIB_FILES) $(XRL_FILES) $(YRL_FILES); \
	fi
	$(makedep_verbose) $(call erlang,$(call makedep.erl,$@))
endif

ifeq ($(IS_APP)$(IS_DEP),)
# Rebuild generated files when a Makefile changes. $(PROJECT).d is
# excluded so the stamp and the dependency file do not depend on each other.
$(ERLANG_MK_TMP)/last-makefile-change: $(filter-out $(PROJECT).d,$(MAKEFILE_LIST)) | $(ERLANG_MK_TMP)
	$(verbose) touch $@
endif

$(PROJECT).d::
	$(verbose) :

ifeq ($(ERLC_PER_FILE),1)
ERL_BEAM_FILES = $(addprefix ebin/,$(patsubst %.erl,%.beam,$(notdir $(filter-out $(ERLC_EXCLUDE_PATHS),$(ERL_FILES)))))
CORE_BEAM_FILES = $(addprefix ebin/,$(patsubst %.core,%.beam,$(notdir $(filter-out $(ERLC_EXCLUDE_PATHS),$(CORE_FILES)))))
COMPILE_FIRST_BEAMS = $(addprefix ebin/,$(patsubst %.erl,%.beam,$(notdir $(COMPILE_FIRST_PATHS))))

define compile_erl_target
ebin/$(notdir $(basename $1)).beam: $1 $(if $(filter ebin/$(notdir $(basename $1)).beam,$(COMPILE_FIRST_BEAMS)),,$(COMPILE_FIRST_BEAMS)) $(MAKEFILE_CHANGE) | ebin/
	$$(erlc_verbose_per_file) ERLC_USE_SERVER=true erlc -v $$(if $$(IS_DEP),$$(filter-out -Werror,$$(ERLC_OPTS)),$$(ERLC_OPTS)) -o ebin/ \
		-pa ebin/ -I include/ $$<
endef

$(foreach f,$(filter-out $(ERLC_EXCLUDE_PATHS),$(ERL_FILES) $(CORE_FILES)),$(eval $(call compile_erl_target,$f)))
endif

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

ebin/$(PROJECT).app:: $(if $(filter 1,$(ERLC_PER_FILE)),$(ERL_BEAM_FILES) $(CORE_BEAM_FILES),$(ERL_FILES) $(CORE_FILES)) $(wildcard src/$(PROJECT).app.src) $(EX_FILES) $(HEEX_FILES) $(MAKEFILE_CHANGE)
ifneq ($(ERLC_PER_FILE),1)
	$(eval FILES_TO_COMPILE := $(filter-out $(EX_FILES) $(HEEX_FILES) src/$(PROJECT).app.src,$?))
	$(if $(filter $(MAKEFILE_CHANGE),$?),$(call compile_erl,$(filter-out $(EX_FILES) src/$(PROJECT).app.src,$(ERL_FILES) $(CORE_FILES))),$(if $(strip $(FILES_TO_COMPILE)),$(call compile_erl,$(FILES_TO_COMPILE))))
endif
	$(if $(filter $(ELIXIR),disable),,$(if $(strip $(EX_FILES)),$(if $(filter $(MAKEFILE_CHANGE) $(EX_FILES) $(HEEX_FILES),$?),$(elixirc_verbose) $(eval MODULES := $(shell $(call erlang,$(call compile_ex.erl,$(EX_FILES)),-pa $(CURDIR)/ebin))),$(eval MODULES := $(patsubst %,'%',$(notdir $(basename $(wildcard ebin/Elixir.*.beam))))))))
	$(eval ELIXIR_COMP_FAILED := $(if $(filter _ERROR_,$(firstword $(MODULES))),true,false))
# Older git versions do not have the --first-parent flag. Do without in that case.
	$(verbose) if $(ELIXIR_COMP_FAILED); then exit 1; fi
	$(eval GITDESCRIBE := $(shell git describe --dirty --abbrev=7 --tags --always --first-parent 2>/dev/null \
		|| git describe --dirty --abbrev=7 --tags --always 2>/dev/null || true))
	$(eval MODULES := $(sort $(MODULES) $(patsubst %,'%',$(notdir $(basename \
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
	$(gen_verbose) rm -rf $(PROJECT).d ebin priv/mibs $(XRL_ERL_FILES) $(YRL_ERL_FILES) \
		$(addprefix include/,$(patsubst %.mib,%.hrl,$(notdir $(MIB_FILES)))) \
		$(addprefix include/,$(patsubst %.asn1,%.hrl,$(notdir $(ASN1_FILES)))) \
		$(addprefix include/,$(patsubst %.asn1,%.asn1db,$(notdir $(ASN1_FILES)))) \
		$(addprefix src/,$(patsubst %.asn1,%.erl,$(notdir $(ASN1_FILES))))

endif

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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
test-deps: deps | $(ERLANG_MK_TMP)/dep_built
ifneq ($(ALL_TEST_DEPS_DIRS),)
	$(verbose) missing=; for dep in $(ALL_TEST_DEPS_DIRS); do \
		[ -e $$dep ] || missing="$$missing $$dep"; \
	done; \
	if [ -n "$$missing" ]; then $(MAKE) --no-print-directory $$missing; fi
	$(verbose) set -e; for dep in $(ALL_TEST_DEPS_DIRS) ; do \
		if [ -z "$(strip $(FULL))" ] && [ ! -L $$dep ] && [ -f $(ERLANG_MK_TMP)/dep_built/`basename $$dep` ]; then \
			:; \
		else \
			$(MAKE) -C $$dep IS_DEP=1; \
			if [ ! -L $$dep ] && [ -d $$dep/ebin ]; then touch $(ERLANG_MK_TMP)/dep_built/`basename $$dep`; fi; \
		fi \
	done
endif
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
test-build:: $(if $(wildcard src),$(if $(wildcard $(ERLANG_MK_TMP)/$(PROJECT).test),,beam-cache-restore-test)) $(if $(IS_APP),,deps test-deps)
# We already compiled everything when IS_APP=1.
ifndef IS_APP
ifneq ($(wildcard src),)
	$(verbose) $(MAKE) --no-print-directory $(PROJECT).d ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
	$(verbose) $(MAKE) --no-print-directory app-build ERLC_OPTS="$(call escape_dquotes,$(TEST_ERLC_OPTS))"
	$(gen_verbose) touch $(ERLANG_MK_TMP)/$(PROJECT).test
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
	$(gen_verbose) touch $(ERLANG_MK_TMP)/$(PROJECT).test
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

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
# Copyright (c) 2014, Enrique Fernandez <enrique.fernandez@erlang-solutions.com>
# This file is contributed to erlang.mk and subject to the terms of the ISC License.

.PHONY: eunit apps-eunit

# Eunit can be disabled by setting this to any other value.
EUNIT ?= system

ifeq ($(EUNIT),system)

# Configuration

EUNIT_OPTS ?=
EUNIT_ERL_OPTS ?=
EUNIT_TEST_SPEC ?= $1

# Core targets.

tests:: eunit

help::
	$(verbose) printf "%s\n" "" \
		"EUnit targets:" \
		"  eunit       Run all the EUnit tests for this project" \
		"" \
		"Pass t=mod or t=mod:case to run one module or test."

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

endif

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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
		"  shell       Run an erlang shell with SHELL_OPTS or reasonable default" \
		"              Set RELOAD=1 to reload code automatically."

# Plugin-specific targets.

$(foreach dep,$(SHELL_DEPS),$(eval $(call dep_target,$(dep))))

ifneq ($(SKIP_DEPS),)
build-shell-deps:
else
build-shell-deps: $(ALL_SHELL_DEPS_DIRS) | $(ERLANG_MK_TMP)/dep_built
	$(verbose) set -e; for dep in $(ALL_SHELL_DEPS_DIRS) ; do \
		if [ -z "$(strip $(FULL))" ] && [ ! -L $$dep ] && [ -f $(ERLANG_MK_TMP)/dep_built/`basename $$dep` ]; then \
			:; \
		else \
			$(MAKE) -C $$dep IS_DEP=1; \
			if [ ! -L $$dep ] && [ -d $$dep/ebin ]; then touch $(ERLANG_MK_TMP)/dep_built/`basename $$dep`; fi; \
		fi \
	done
endif

ifdef RELOAD
define shell_reload.erl
	spawn(fun F() ->
		case c:lm() of
			[] -> ok;
			Reloaded -> io:format("reloaded ~p~n", [Reloaded])
		end,
		receive after 5000 -> F() end
	end).
endef
SHELL_RELOAD_OPTS = -eval "$(subst $(newline),,$(call escape_dquotes,$(call shell_reload.erl)))"
else
SHELL_RELOAD_OPTS =
endif

shell:: build-shell-deps
	$(gen_verbose) $(SHELL_ERL) -pa $(SHELL_PATHS) $(SHELL_RELOAD_OPTS) $(SHELL_OPTS)

# Copyright (c) Loïc Hoguin <essen@ninenines.eu>
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
	Ms0 = cover:imported_modules(),
	Exclude = [$(call comma_list,$(COVER_EXCLUDE_MODS))],
	Ms = [M || M <- Ms0, not lists:member(M, Exclude)],
	[cover:analyse_to_file(M, "$(COVER_REPORT_DIR)/" ++ atom_to_list(M)
		++ ".COVER.html", [html])  || M <- Ms],
	Report = [begin
		{result, [R], []} = cover:analyse([M], module),
		R
	end || M <- Ms],
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
