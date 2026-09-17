#!/usr/bin/env bash
set -u

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ccdc-perimeter-test.XXXXXX") || exit 1
trap 'rm -rf -- "$tmp"' EXIT INT TERM HUP
pass=0 fail=0
ok() { pass=$((pass + 1)); printf 'ok %s - %s\n' "$((pass + fail))" "$1"; }
no() { fail=$((fail + 1)); printf 'not ok %s - %s\n' "$((pass + fail))" "$1"; }

mkdir -p "$tmp/bin"
cat >"$tmp/bin/nmap" <<'EOF'
#!/usr/bin/env bash
prefix=''
while [ "$#" -gt 0 ]; do
  case "$1" in -oA) prefix=$2; shift 2 ;; *) shift ;; esac
done
printf 'Host: 10.77.0.10 ()  Ports: 22/open/tcp//ssh///, 8080/open/tcp//http-proxy///\n' >"$prefix.gnmap"
printf 'fake normal output\n' >"$prefix.nmap"
printf '<nmaprun/>\n' >"$prefix.xml"
EOF
chmod +x "$tmp/bin/nmap"
cat >"$tmp/test.env" <<EOF
CCDC_PERIMETER_SCOPE="10.77.0.0/24"
CCDC_PERIMETER_EVIDENCE_DIR="$tmp/evidence"
CCDC_PERIMETER_TCP_RATE="1000"
CCDC_PERIMETER_UDP_RATE="100"
CCDC_ALLOWED_TCP_PORTS="22"
CCDC_ALLOWED_UDP_PORTS=""
EOF

PATH="$tmp/bin:$PATH" "$ROOT/workstation/perimeter.sh" --config "$tmp/test.env" --tcp >"$tmp/dry.out" 2>&1
if grep -q 'no packets sent' "$tmp/dry.out" && [ ! -d "$tmp/evidence" ]; then ok 'scan needs explicit apply and scope confirmation'; else no 'dry run created evidence or did not explain itself'; fi

PATH="$tmp/bin:$PATH" "$ROOT/workstation/perimeter.sh" --config "$tmp/test.env" --tcp --apply --confirm-scope >"$tmp/scan.out" 2>&1
gnmap=$(find "$tmp/evidence" -name '*.gnmap' -type f -print -quit)
if [ -n "$gnmap" ] && grep -q -- '--max-rate 1000' "$tmp/evidence"/*.command && grep -q '10.77.0.0/24' "$tmp/evidence"/*.command; then ok 'TCP scan records a conservative scoped command'; else no 'TCP scan did not save the expected evidence'; fi

"$ROOT/workstation/perimeter.sh" --config "$tmp/test.env" --report "$gnmap" >"$tmp/report.out" 2>&1
if grep -q '| 10.77.0.10 | tcp | 22 | open | ssh | Yes - scored |' "$tmp/report.out" \
   && grep -q '| 10.77.0.10 | tcp | 8080 | open | http-proxy | REVIEW |' "$tmp/report.out"; then ok 'report joins external results to the configured verdict'; else no 'report table is incomplete or misclassified'; cat "$tmp/report.out"; fi

cp "$tmp/test.env" "$tmp/broad.env"
sed -i 's#10\.77\.0\.0/24#10.0.0.0/8#' "$tmp/broad.env"
if ! "$ROOT/workstation/perimeter.sh" --config "$tmp/broad.env" --plan >"$tmp/broad.out" 2>&1 \
   && grep -q 'from /16 through /32' "$tmp/broad.out"; then ok 'unsafe broad CIDRs are rejected before a scan can be planned'; else no 'broad CIDR passed scope validation'; fi

printf 'perimeter self-test: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
