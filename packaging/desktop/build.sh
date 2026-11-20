#!/usr/bin/env bash
# Build only a committed source snapshot; never package working-tree/user files.
set -euo pipefail
if [[ $# != 2 || ! $1 =~ ^[0-9a-f]{40}$ ]]; then
    printf 'Usage: bash packaging/desktop/build.sh FULL_SOURCE_COMMIT NEW_OUTPUT_DIRECTORY\n' >&2
    exit 2
fi
source_commit=$1
output=$(realpath -m -- "$2")
repo=$(git rev-parse --show-toplevel)
resolved=$(git -C "$repo" rev-parse --verify "$source_commit^{commit}")
[[ $resolved == "$source_commit" ]] || { printf 'Source commit did not resolve exactly\n' >&2; exit 1; }
[[ ! -e $output ]] || { printf 'Output directory already exists: %s\n' "$output" >&2; exit 1; }
epoch=$(git -C "$repo" show -s --format=%ct "$source_commit")
context=$(mktemp -d -t rbwbio-desktop-source.XXXXXXXX)
trap 'rm -rf -- "$context"' EXIT
git -C "$repo" archive --format=tar "$source_commit" | tar -xf - -C "$context"
mkdir -p -- "$output"
docker buildx build --platform linux/amd64 --progress=plain \
    --file "$context/packaging/desktop/Dockerfile" --target artifact \
    --build-arg "SOURCE_COMMIT=$source_commit" --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --output "type=local,dest=$output" "$context"
source_archive="rbwbio-source-$source_commit.tar.gz"
git -C "$repo" archive --format=tar --prefix="rbwbio-$source_commit/" "$source_commit" \
    | gzip -n -9 >"$output/$source_archive"
(cd "$output" && sha256sum "$source_archive" >"$source_archive.sha256")
printf 'Built source commit %s into %s\n' "$source_commit" "$output"
