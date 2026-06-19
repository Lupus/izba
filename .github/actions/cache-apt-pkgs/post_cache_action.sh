#!/bin/bash

# Fail on any error.
set -e

# Include library.
script_dir="$(dirname -- "$(realpath -- "${0}")")"
source "${script_dir}/lib.sh"
# lib.sh unconditionally runs `set +e` (it uses exit-status conditionals
# internally), which cancels the `set -e` above. Re-enable it so a non-zero
# exit from the restore_pkgs.sh / install_and_cache_pkgs.sh subprocess dispatched
# below aborts this step instead of letting save-cache persist an empty
# ~/cache-apt-pkgs that poisons every future warm run. Mirrors the same fix in
# install_and_cache_pkgs.sh and pre_cache_action.sh.
set -e

# Directory that holds the cached packages.
cache_dir="${1}"

# Root directory to untar the cached packages to.
# Typically filesystem root '/' but can be changed for testing.
# WARNING: If non-root, this can cause errors during install script execution.
cache_restore_root="${2}"

# Indicates that the cache was found.
cache_hit="${3}"

# Cache and execute post install scripts on restore.
execute_install_scripts="${4}"

# Debug mode for diagnosing issues.
debug="${5}"
test "${debug}" = "true" && set -x

# Repositories to add before installing packages.
add_repository="${6}"

# List of the packages to use.
packages="${@:7}"

if test "${cache_hit}" = "true"; then
  ${script_dir}/restore_pkgs.sh "${cache_dir}" "${cache_restore_root}" "${execute_install_scripts}" "${debug}"
else
  ${script_dir}/install_and_cache_pkgs.sh "${cache_dir}" "${debug}" "${add_repository}" ${packages}
fi

log_empty_line
