#!/usr/bin/env bash

# Prints the section of CHANGELOG.md for version $1 (as "0.2.0"): the notes of that version's release.
# Fails, saying why, when the changelog has no such section, so a tag never publishes a release
# without notes. The version itself comes from the tag (git describe), so there is no file to match.
set -euo pipefail

version="$1"
# From "## <version>" (alone or followed by its date) to the next "## ".
notes=$(awk -v v="$version" '{ sub(/\r$/, "") } /^## / { if (found) exit; found = ($0 == "## " v || index($0, "## " v " ") == 1); next } found' CHANGELOG.md)
if [ -z "$(printf '%s' "$notes" | tr -d '[:space:]')" ]; then
    echo "CHANGELOG.md has no section \"## $version\": write the notes before tagging" >&2
    exit 1
fi
printf '%s\n' "$notes"
