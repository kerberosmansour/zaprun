#!/usr/bin/env bash
set -euo pipefail

# First-arg dispatch: when the container is invoked as
# `docker run --rm <image> zaprun <args...>`, hand off to the baked-in CLI.
# We compare $1 by literal string equality (no regex, no shell evaluation of
# $1's contents) so attacker-controlled argv strings cannot inject commands.
# Anything else falls through to the legacy --target/--output-dir/--policy
# entrypoint below, which preserves the existing dast-spike-entrypoint contract.
if [ "${1:-}" = "zaprun" ]; then
  shift
  exec /usr/local/bin/zaprun "$@"
fi

export _JAVA_OPTIONS="${_JAVA_OPTIONS:--Xmx4g -Xss2m -XX:+UseG1GC -XX:MaxGCPauseMillis=200}"
export DAST_SPIKE_BROWSER_ID="${DAST_SPIKE_BROWSER_ID:-firefox-headless}"
export DAST_SPIKE_DOM_XSS_ENABLED="${DAST_SPIKE_DOM_XSS_ENABLED:-0}"

TARGET=""
OUTPUT_DIR="/zap/wrk/output"
POLICY="/zap/policies/policy-pr.yml"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      TARGET="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --policy)
      POLICY="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$TARGET" ]; then
  echo "--target is required" >&2
  exit 2
fi

mkdir -p "$OUTPUT_DIR"

ZAP_OPTS=(
  "-config" "scanner.threadPerHost=1"
  "-config" "spider.thread=1"
  "-config" "globalexcludeurl.url_list.url(0).regex=^https?://content-signature.*\\.mozilla\\.net/.*$"
  # NOTE: no spaces in the description value — ZAP_OPTS is joined into a single
  # string via "${ZAP_OPTS[*]}" and passed through `zap-baseline.py -z "..."`,
  # which word-splits the string before handing it to ZAP. A space here would
  # make ZAP treat the second word as a separate (unrecognised) argument.
  "-config" "globalexcludeurl.url_list.url(0).description=Firefox-internal"
  "-config" "globalexcludeurl.url_list.url(0).enabled=true"
)

if [ "$DAST_SPIKE_DOM_XSS_ENABLED" = "1" ]; then
  ZAP_OPTS+=(
    "-config" "rules.domxss.browserid=${DAST_SPIKE_BROWSER_ID}"
    "-config" "scanner.scanPolicy.rule.40026.strength=LOW"
  )
else
  ZAP_OPTS+=("-config" "scanner.scanPolicy.rule.40026.enabled=false")
fi

# ZAP 2.17's zap-baseline.py / zap-api-scan.py use the Automation Framework
# internally, which resolves report-output paths RELATIVE to /zap/wrk/.
# An absolute path like `/zap/wrk/output/zap-report.html` gets double-prefixed
# to `/zap/wrk/zap/wrk/output/zap-report.html` and report generation fails
# with NoSuchFileException. Convert to a path relative to /zap/wrk/.
case "$OUTPUT_DIR" in
  /zap/wrk/*)
    REPORT_REL_DIR="${OUTPUT_DIR#/zap/wrk/}"
    ;;
  *)
    # Unusual override — pass through verbatim. May not work, but preserves
    # whatever contract the caller intended.
    REPORT_REL_DIR="$OUTPUT_DIR"
    ;;
esac

if [[ "$TARGET" = http://* || "$TARGET" = https://* ]]; then
  zap-baseline.py \
    -t "$TARGET" \
    -r "$REPORT_REL_DIR/zap-report.html" \
    -J "$REPORT_REL_DIR/zap-report.json" \
    -T 120 \
    -z "${ZAP_OPTS[*]}"
else
  zap-api-scan.py \
    -t "$TARGET" \
    -f openapi \
    -r "$REPORT_REL_DIR/zap-report.html" \
    -J "$REPORT_REL_DIR/zap-report.json" \
    -T 120 \
    -z "${ZAP_OPTS[*]}"
fi
