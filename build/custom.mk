# Include custom targets and environment variables here

## Builds the combined bundle, then a smaller single-platform bundle for each
## supported server executable (dist/<id>-<version>-<os>-<arch>.tar.gz).
.PHONY: dist-per-platform
dist-per-platform: dist
	sh ./build/per-platform-bundles.sh
