#!/bin/sh
# Shows or bumps the "version" field in plugin.json (semver x.y.z).
# Usage: build/bump-version.sh show|patch|minor|major
set -eu

file=plugin.json
current=$(sed -n 's/^  "version": "\([0-9]*\.[0-9]*\.[0-9]*\)",$/\1/p' "$file")
if [ -z "$current" ]; then
	echo "error: no x.y.z \"version\" found in $file" >&2
	exit 1
fi

major=${current%%.*}
rest=${current#*.}
minor=${rest%%.*}
patch=${rest#*.}

case "${1:-show}" in
show)
	echo "$current"
	exit 0
	;;
patch) patch=$((patch + 1)) ;;
minor) minor=$((minor + 1)); patch=0 ;;
major) major=$((major + 1)); minor=0; patch=0 ;;
*)
	echo "usage: $0 show|patch|minor|major" >&2
	exit 1
	;;
esac

next="$major.$minor.$patch"
sed -i.bak "s/^  \"version\": \"$current\",$/  \"version\": \"$next\",/" "$file"
rm -f "$file.bak"
echo "plugin.json: $current -> $next"
echo "Next: add a \"## [$next]\" section to CHANGELOG.md, commit, and push to main."
