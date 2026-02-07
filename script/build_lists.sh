#!/usr/bin/env bash
#
# This script builds the lists at: github.com/theouterspaced/polturk-threatfeed
#
# Upstream Sources:
# https://hole.cert.pl/domains/v2/domains.txt
# https://www.usom.gov.tr/url-list.txt
#
# "bash build_lists.sh /path/to/output/directory"
#

############################################
## initialize stuff

if [ "${1:-}" != "" ]; then
    OUT_DIR="$1"
else
    echo "== need output path... exiting w/o run! =="
    exit 1
fi

URLS=(
    "https://hole.cert.pl/domains/v2/domains.txt"
    "https://www.usom.gov.tr/url-list.txt"
)

LIST_DIR="$HOME/files/git/polturk-threatfeed/script/list_history"
HIST_TAR="${LIST_DIR}.tar.gz"

MAX_TRIES=3
COOLDOWN=$((300))

############################################
## helper functions

# check for tools
need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: missing required command: $1" >&2
        exit 1
    }
}

# list history open
restore_history() {
    mkdir -p "$LIST_DIR"
    if [ -f "$HIST_TAR" ]; then
        tar -xzf "$HIST_TAR" -C "$LIST_DIR"
    fi
}

# list history close
archive_history() {
    mkdir -p "$LIST_DIR"
    tar -czf "$HIST_TAR" -C "$LIST_DIR" .
    rm -rf -- "$LIST_DIR"/*
    rm -rf -- "$LIST_DIR"/.[!.]* "$LIST_DIR"/..?* 2>/dev/null || true
    rm -rf -- "$LIST_DIR"
}

# wget upstream with retries
wget_retry() {
    local url="$1" out="$2"
    local try=1
    while [ "$try" -le "$MAX_TRIES" ]; do
        rm -f "$out"
        if wget -q -O "$out" "$url" && [ -s "$out" ]; then
            return 0
        fi
        echo "wget failed ($try/$MAX_TRIES): $url" >&2
        if [ "$try" -lt "$MAX_TRIES" ]; then
            echo "waiting ${COOLDOWN}s..." >&2
            sleep "$COOLDOWN"
        fi
        try=$((try + 1))
    done
    return 1
}

# rotate historical lists
prune_history() {
    mkdir -p "$LIST_DIR"
    local files
    shopt -s nullglob
    files=( "$LIST_DIR"/list-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9].txt )
    shopt -u nullglob
    if [ ${#files[@]} -eq 0 ]; then
        return 0
    fi
    keep="$(printf "%s\n" "${files[@]}" | sort | tail -n 10)"
    for f in "${files[@]}"; do
        printf "%s\n" "$keep" | grep -Fxq "$f" || rm -f "$f"
    done
}

# write final lists
write_with_header() {
    local out_file="$1"
    shift
    mkdir -p "$(dirname "$out_file")"
    {
        echo "# $(date -u)"
        echo "# A combined domains blocklist from Poland and Türkiye CERT threat feeds."
        echo "# All credit resides with these upstream sources:"
        echo "# - CERT Polska Team: https://cert.pl/en/warning-list"
        echo "# - USOM CERT Republic of Türkiye: https://www.usom.gov.tr/en/about-us"
        echo "# github.com/theouterspaced/polturk-threatfeed"
        echo "##"
        "$@"
    } > "$out_file"
}

# write final lists (adblock specific)
write_with_header_adblock() {
    local out_file="$1"
    shift
    mkdir -p "$(dirname "$out_file")"
    {
        echo "! $(date -u)"
        echo "! A combined domains blocklist from Poland and Türkiye CERT threat feeds."
        echo "! All credit resides with these upstream sources:"
        echo "! - CERT Polska Team: https://cert.pl/en/warning-list"
        echo "! - USOM CERT Republic of Türkiye: https://www.usom.gov.tr/en/about-us"
        echo "! github.com/theouterspaced/polturk-threatfeed"
        echo "!"
        "$@"
    } > "$out_file"
}

############################################
## main
echo "== starting... =="
need_cmd wget
need_cmd awk
need_cmd sort
need_cmd mktemp
need_cmd wc
need_cmd tr
need_cmd tar
need_cmd gzip

restore_history

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/listbuild.working")"
trap 'rm -rf "$WORKDIR"' EXIT

RAW="$WORKDIR/raw_combined.txt"
: > "$RAW"

# download source lists
echo "== downloading source lists =="
for url in "${URLS[@]}"; do
    base="$(printf '%s' "$url" | awk -F/ '{print $NF}')"
    fn="$WORKDIR/$base"
    echo "  - $url"
    if ! wget_retry "$url" "$fn"; then
        echo "ERROR: failed to download after ${MAX_TRIES} tries: $url" >&2
    fi
    cat "$fn" >> "$RAW"
    printf "\n" >> "$RAW"
done

# clean source lists
echo "== cleaning source lists =="
LIST0="$WORKDIR/list_0.txt"
awk '
function has_ipv4(line,ip,a,n,i,ok,rest) {
    rest = line
    while (match(rest, /([0-9]{1,3}\.){3}[0-9]{1,3}/)) {
        ip = substr(rest, RSTART, RLENGTH)
        n = split(ip, a, ".")
        ok = (n == 4)
        for (i = 1; i <= 4; i++) if (a[i] < 0 || a[i] > 255) ok = 0
        if (ok) return 1
        rest = substr(rest, RSTART + RLENGTH)
    }
    return 0
}
function has_ipv6(line) {
    return (line ~ /::/) || (line ~ /[0-9A-Fa-f]{0,4}(:[0-9A-Fa-f]{0,4}){2,}/)
}
{
    s = $0
    if (has_ipv4(s) || has_ipv6(s)) next
    if (s ~ /^\./) next
    if (s !~ /\./) next
    if (s ~ /\//) next
    if (s == "") next
    sub(/[[:space:]]+$/, "", s)
    s = tolower(s)
    print s
}
' "$RAW" | LC_ALL=C sort -u > "$LIST0"

# rotate historical lists and save new list
mkdir -p "$LIST_DIR"
TODAY_UTC="$(date -u +%Y%m%d-%H%M)"
TODAY_FILE="$LIST_DIR/list-${TODAY_UTC}.txt"
cp -f "$LIST0" "$TODAY_FILE"
prune_history

# build final list files (combine domains from past 10 lists. do various formats
echo "== building final list =="
MERGED="$WORKDIR/merged_all.txt"
shopt -s nullglob
files=( "$LIST_DIR"/list-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9].txt )
shopt -u nullglob
if [ ${#files[@]} -eq 0 ]; then
    : > "$MERGED"
else
    cat "${files[@]}" | LC_ALL=C sort -u > "$MERGED"
fi
mkdir -p "$OUT_DIR"
write_with_header "$OUT_DIR/domains.txt" cat "$MERGED"
write_with_header "$OUT_DIR/hosts.txt" awk '{print "0.0.0.0 " $0}' "$MERGED"
write_with_header "$OUT_DIR/wildcard.txt" awk '{print "*." $0}' "$MERGED"
write_with_header "$OUT_DIR/dnsmasq.txt" awk '{print "local=/" $0 "/"}' "$MERGED"
write_with_header_adblock "$OUT_DIR/adblock.txt"  awk '{print "||" $0 "^"}' "$MERGED"

archive_history

echo "== ...done =="
# eof
