#!/usr/bin/env bash
# 把 install.sh 里新增的纯函数段抽出来，在 bash 中做行为验证。
# 只测 normalize_trusted_proxies（纯字符串逻辑，无 docker 依赖）。
set -uo pipefail

SRC="${1:-install.sh}"
OUT=".tmp_normalize_cases.sh"

# 抽出函数体：从 normalize_trusted_proxies() 到下一个顶层函数前
awk '
  /^normalize_trusted_proxies\(\) \{/ { grab=1 }
  grab && /^### / { exit }
  grab { print }
' "$SRC" > "$OUT"

echo "--- extracted ($(wc -l < "$OUT") lines) ---"
head -3 "$OUT"

# 提供函数里用到的 log 助手
cat > .tmp_harness.sh <<'EOS'
log_error() { echo "LOG_ERROR: $*" >&2; }
log_warn() { echo "LOG_WARN: $*" >&2; }
EOS

run_case() {
  local desc="$1" input="$2" expect="$3"
  local got
  got="$(
    source .tmp_harness.sh
    source "$OUT"
    normalize_trusted_proxies "$input"
  )"
  if [[ "$got" == "$expect" ]]; then
    echo "PASS  ${desc}"
  else
    echo "FAIL  ${desc}"
    echo "        input:  $input"
    echo "        expect: $expect"
    echo "        got:    $got"
    return 1
  fi
}

fails=0
run_case "bare IPv4 -> /32"          "203.0.113.7"                 "203.0.113.7/32"        || fails=$((fails+1))
run_case "CIDR kept"                 "203.0.113.0/24"              "203.0.113.0/24"        || fails=$((fails+1))
run_case "two entries sorted"        "203.0.113.0/24,198.51.100.0/24" "198.51.100.0/24,203.0.113.0/24" || fails=$((fails+1))
run_case "duplicates removed"        "203.0.113.0/24,203.0.113.0/24" "203.0.113.0/24"      || fails=$((fails+1))
run_case "whitespace trimmed"        " 10.0.0.0/8 , 192.168.0.0/16 " "10.0.0.0/8,192.168.0.0/16" || fails=$((fails+1))
run_case "empty segments skipped"    "10.0.0.0/8,,192.168.0.0/16"  "10.0.0.0/8,192.168.0.0/16" || fails=$((fails+1))
run_case "reject 0.0.0.0/0"          "0.0.0.0/0"                   ""                      || fails=$((fails+1))
run_case "reject ::/0"               "::/0"                        ""                      || fails=$((fails+1))
run_case "reject bad prefix len"     "10.0.0.0/33"                 ""                      || fails=$((fails+1))
run_case "reject all-empty"          " , , "                      ""                      || fails=$((fails+1))
run_case "mixed valid+rejected"      "10.0.0.0/8,0.0.0.0/0"        ""                      || fails=$((fails+1))

echo ""
echo "fails=$fails"
rm -f "$OUT" .tmp_harness.sh
exit $([ "$fails" -eq 0 ] && echo 0 || echo 1)
