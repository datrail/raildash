#!/usr/bin/env bash
# DR-81 two-mode stack preflight — static checks in seconds, no Docker daemon
# needed beyond `docker compose config`. Run from the raildash checkout root.
pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

echo "== syntax =="
chk "compose base YAML"        "python3 -c \"import yaml;yaml.safe_load(open('docker-compose.yml'))\""
chk "compose build override"   "python3 -c \"import yaml;yaml.safe_load(open('docker-compose.build.yml'))\""
chk "release workflow YAML"    "python3 -c \"import yaml;yaml.safe_load(open('.github/workflows/container-release.yml'))\""
chk "Makefile parses (stack)"       "make -n stack RAILMON_TAG=v1 RAILDASH_TAG=v1"
chk "Makefile parses (stack-test)"  "make -n stack-test"
chk "python still compiles"    "python3 -m py_compile raildash/*.py webhook_server.py"

echo "== no clone machinery left =="
chk "no git clone in Makefile"      "! grep -q 'git clone' Makefile"
chk "no RAILMON_REPO/REF"           "! grep -qE 'RAILMON_(REPO|REF)' Makefile"
chk "no rm -rf railmon"             "! grep -q 'rm -rf railmon' Makefile"
chk "no preflight.sh committed"     "! git ls-files --error-unmatch preflight.sh"

echo "== two modes =="
chk "stack-local target"            "grep -q '^stack-local: railmon-src-check' Makefile"
chk "registry stack requires tags"  "grep -q 'registry mode needs both tags' Makefile"
chk "v is stripped from tags"       "grep -q 'patsubst v%,%' Makefile"
chk "shared _stack-up (one copy)"   "grep -q '^_stack-up:' Makefile"
chk "src-check greps both env vars" "grep -q 'grep -q RAILMON_SESSION_ID' Makefile"
chk "build override uses RAILMON_SRC" "grep -q 'RAILMON_SRC:-../railmon' docker-compose.build.yml"
chk "base images are ghcr"          "grep -q 'ghcr.io/datrail/railmon' docker-compose.yml && grep -q 'ghcr.io/datrail/raildash' docker-compose.yml"

echo "== carried-over review fixes =="
chk "docker wait exit code checked" "grep -q \"railmon's demo exited\" Makefile"
chk "container id quoted"           "grep -q 'docker wait \"' Makefile"
chk "import failure restarts dash"  "grep -q 'the file import failed; the dashboard was restarted' Makefile"
chk "readiness loop guarded"        "grep -q 'raildash did not come back healthy' Makefile"
chk "stack-test trap down -v"       "grep -qE \"trap '.*down -v' EXIT\" Makefile"
chk "assertion scoped to session"   "grep -q 'session_id=\$(DEMO_SESSION_ID)' Makefile"
chk "asserts webhook delivered"     "grep -q 'webhook path did not deliver' Makefile"
chk "assertions use parsed total"   "grep -q 'total=\$\$((inserted + duplicate))' Makefile"
chk "quoted DEMO_SESSION_ID"        "grep -q -- '--session-id \"\$(DEMO_SESSION_ID)\"' Makefile"
chk "cites locking_mode=EXCLUSIVE"  "grep -q 'locking_mode=EXCLUSIVE' Makefile docker-compose.yml"
chk "no -shm claim anywhere"        "! grep -q 'shm' README.md docker-compose.yml docker-compose.build.yml"
chk "dockerignore excludes railmon" "grep -qx 'railmon' .dockerignore"

echo "== DR-20 content intact, additions only =="
for m in "credential headers are redacted before storage" \
         "127.0.0.1:8000:8000" \
         "One process owns a database at a time" \
         "rotate any"; do
  chk "README retains: ${m:0:44}" "grep -q '$m' README.md"
done
chk "no removals from master in README"   "[ -z \"\$(git diff master -- README.md | grep '^-' | grep -v '^---')\" ]"
chk "no removals from master in Makefile" "[ -z \"\$(git diff master -- Makefile | grep '^-' | grep -v '^---' | grep -v '^-[.]PHONY:')\" ]"

echo "== guards fire (sandboxed, nothing touched) =="
t=$(mktemp -d)
if ! make railmon-src-check RAILMON_SRC="$t/none" >/dev/null 2>&1; then ok "src-check rejects missing checkout"; else no "src-check rejects missing checkout"; fi
mkdir -p "$t/old/tools/local-demo"; echo 'x' > "$t/old/tools/local-demo/run_local_demo.sh"
if ! make railmon-src-check RAILMON_SRC="$t/old" >/dev/null 2>&1; then ok "src-check rejects no-passthrough checkout"; else no "src-check rejects no-passthrough checkout"; fi
printf 'RAILMON_WEBHOOK_URL\nRAILMON_SESSION_ID\n' > "$t/old/tools/local-demo/run_local_demo.sh"
if make railmon-src-check RAILMON_SRC="$t/old" >/dev/null 2>&1; then ok "src-check accepts a good checkout"; else no "src-check accepts a good checkout"; fi
if ! make stack 2>/dev/null >/dev/null; then ok "registry stack refuses without tags"; else no "registry stack refuses without tags"; fi
rm -rf "$t"

echo "== DCO =="
n_commits=$(git rev-list --count master..HEAD 2>/dev/null || echo 0)
n_signed=$(git log master..HEAD --format='%(trailers:key=Signed-off-by)' 2>/dev/null | grep -c 'Signed-off-by' || true)
if [ "$n_commits" -gt 0 ] && [ "$n_commits" = "$n_signed" ]; then ok "all $n_commits commits signed off"
else no "signed-off commits: $n_signed of $n_commits -- run: git rebase --signoff master"; fi

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ] && echo "-> ready for /rail-review" || echo "-> fix the above first"
exit "$fail"
