#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "FAIL: $*" >&2; exit 1; }
# All entry points must build before stopping/replacing running containers.
for spec in 'install.sh:do_update_interactive' 'install.sh:quick_update' 'deploy.sh:start_services'; do
  file=${spec%%:*}; fn=${spec#*:}
  body=$(sed -n "/^${fn}() {/,/^}/p" "$file")
  [[ "$body" == *'build --pull newapi-tools'* ]] || fail "$fn does not build modified source"
  [[ "$body" != *'git fetch origin 2>/dev/null || true'* ]] || fail 'update silently ignores fetch failure'
  build_line=$(printf '%s\n' "$body" | grep -n 'build --pull newapi-tools' | head -1 | cut -d: -f1)
  stop_line=$(printf '%s\n' "$body" | grep -nE ' down|docker rm -f' | head -1 | cut -d: -f1 || true)
  [[ -z "$stop_line" || "$build_line" -lt "$stop_line" ]] || fail "$fn stops service before build"
done
grep -q 'git remote set-url origin "\$REPO_URL"' install.sh || fail 'existing installation keeps upstream remote'
grep -q 'pull_policy: never' docker-compose.yml || fail 'local application image may be pulled'
echo 'PASS: source update paths build fork before replacing services'
