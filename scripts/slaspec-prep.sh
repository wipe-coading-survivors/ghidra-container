#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BUILD_DIR="${BUILD_DIR:-build}"

die() {
    echo "slaspec-prep: $*" >&2
    exit 1
}

[ -n "${SYNDICATE_TARBALL_URL:-}" ] || die "SYNDICATE_TARBALL_URL is not set"
[ -n "${SYNDICATE_TARBALL_SHA256:-}" ] || die "SYNDICATE_TARBALL_SHA256 is not set"
[ -n "${SLASPEC_PATCH_URL:-}" ] || die "SLASPEC_PATCH_URL is not set"
[ -n "${SLASPEC_PATCH_SHA256:-}" ] || die "SLASPEC_PATCH_SHA256 is not set"

cd "$ROOT"

TARBALL="$BUILD_DIR/downloads/syndicate-tarball.tar.gz"
PATCH_FILE="$BUILD_DIR/downloads/iRISC.slaspec.patch"

mkdir -p "$BUILD_DIR/downloads"

curl -fsSL --retry 3 -o "$TARBALL" "$SYNDICATE_TARBALL_URL" \
    || die "fetch failed: $SYNDICATE_TARBALL_URL"
curl -fsSL --retry 3 -o "$PATCH_FILE" "$SLASPEC_PATCH_URL" \
    || die "fetch failed: $SLASPEC_PATCH_URL"

( cd "$BUILD_DIR/downloads" \
    && printf '%s  %s\n' "$SYNDICATE_TARBALL_SHA256" "$(basename "$TARBALL")" | sha256sum -c - ) \
    || die "integrity check failed: syndicate tarball ($SYNDICATE_TARBALL_SHA256)"
( cd "$BUILD_DIR/downloads" \
    && printf '%s  %s\n' "$SLASPEC_PATCH_SHA256" "$(basename "$PATCH_FILE")" | sha256sum -c - ) \
    || die "integrity check failed: slaspec patch ($SLASPEC_PATCH_SHA256)"

UPSTREAM_SHA=$(grep -m1 '^# upstream-sha256:' "$PATCH_FILE" | awk '{print $3}') \
    || die "patch header: no upstream-sha256 line"
RESULT_SHA=$(grep -m1 '^# result-sha256:' "$PATCH_FILE" | awk '{print $3}') \
    || die "patch header: no result-sha256 line"
[ -n "$UPSTREAM_SHA" ] || die "patch header: empty upstream-sha256"
[ -n "$RESULT_SHA" ] || die "patch header: empty result-sha256"

"$ROOT/scripts/safe-rm" --under "$ROOT" "$ROOT/$BUILD_DIR/processor"
mkdir -p "$BUILD_DIR/processor"

tar -xzf "$TARBALL" --strip-components=1 -C "$BUILD_DIR/processor" \
    || die "tar extract failed: $TARBALL"

INNER="$BUILD_DIR/processor/data/languages/iRISC.slaspec"
[ -f "$INNER" ] || die "tarball does not contain data/languages/iRISC.slaspec"
ACTUAL_UPSTREAM=$(sha256sum "$INNER" | awk '{print $1}')
[ "$ACTUAL_UPSTREAM" = "$UPSTREAM_SHA" ] \
    || die "upstream-sha mismatch: $INNER is $ACTUAL_UPSTREAM, expected $UPSTREAM_SHA"

WORK=$(mktemp -d)
cp "$INNER" "$WORK/iRISC.upstream.slaspec"
patch -p0 --no-backup-if-mismatch -d "$WORK" < "$PATCH_FILE" \
    || die "patch application failed"
[ -f "$WORK/iRISC.slaspec" ] || mv "$WORK/iRISC.upstream.slaspec" "$WORK/iRISC.slaspec"

RESULT_FILE="$WORK/iRISC.slaspec"
[ -f "$RESULT_FILE" ] || die "patch did not produce iRISC.slaspec"
ACTUAL_RESULT=$(sha256sum "$RESULT_FILE" | awk '{print $1}')
[ "$ACTUAL_RESULT" = "$RESULT_SHA" ] \
    || die "result-sha mismatch: $RESULT_FILE is $ACTUAL_RESULT, expected $RESULT_SHA"

cp "$RESULT_FILE" "$INNER"

echo "slaspec-prep: staged $BUILD_DIR/processor (iRISC.slaspec sha256 $ACTUAL_RESULT)"
