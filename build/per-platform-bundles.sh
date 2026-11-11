#!/bin/sh
# Create a smaller, single-platform plugin bundle for each server executable,
# alongside the combined all-platform bundle produced by `make dist`. This lets
# users download only the binary for their server's OS/architecture.
#
# Run after `make dist` (the `dist-per-platform` make target does both).
set -eu

ID=$(./build/bin/manifest id)
VERSION=$(./build/bin/manifest version)
SRC="dist/${ID}"

if [ ! -d "${SRC}" ]; then
	echo "error: ${SRC} not found; run 'make dist' first" >&2
	exit 1
fi

for binpath in "${SRC}"/server/dist/plugin-*; do
	[ -e "${binpath}" ] || continue
	bin=$(basename "${binpath}")            # e.g. plugin-linux-amd64 or plugin-windows-amd64.exe
	platform=${bin#plugin-}                 # e.g. linux-amd64 or windows-amd64.exe
	platform=${platform%.exe}               # e.g. linux-amd64 or windows-amd64

	stage="dist/_pp/${ID}"
	rm -rf dist/_pp
	mkdir -p "${stage}/server/dist"

	# Trim the manifest so it lists only this platform's executable.
	python3 - "${SRC}/plugin.json" "${platform}" > "${stage}/plugin.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
platform = sys.argv[2]
executables = manifest["server"]["executables"]
manifest["server"]["executables"] = {platform: executables[platform]}
print(json.dumps(manifest, indent=4))
PY

	cp "${binpath}" "${stage}/server/dist/${bin}"
	[ -d "${SRC}/assets" ] && cp -r "${SRC}/assets" "${stage}/" || true

	tar -czf "dist/${ID}-${VERSION}-${platform}.tar.gz" -C dist/_pp "${ID}"
	rm -rf dist/_pp
done

echo "Per-platform bundles:"
ls -1 "dist/${ID}-${VERSION}"-*.tar.gz
