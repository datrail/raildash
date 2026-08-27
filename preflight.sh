#!/usr/bin/env bash
# DR-81 preflight — static checks for everything the last three rail-review
# rounds flagged. Seconds, no Docker, does not touch ./railmon.
# Run from the raildash checkout root. Green here != /rail-review will pass,
# but red here means don't bother running it yet.
pass=0; fail=0
ok(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
no(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
chk(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

echo "== syntax =="
chk "Makefile parses (stack)"        "make -n stack"
chk "Makefile parses (stack-test)"   "make -n stack-test"
chk "compose YAML valid"             "python3 -c \"import yaml;yaml.safe_load(open('docker-compose.yml'))\""
chk "python still compiles"          "python3 -m py_compile raildash/*.py webhook_server.py"

echo "== round 1: DR-20 content not clobbered =="
for m in "credential headers are redacted before storage" \
         "127.0.0.1:8000:8000" \
         "loopback interface because RailDash has no authentication" \
         "One process owns a database at a time" \
         "rotate any"; do
  chk "README retains: ${m:0:44}" "grep -q '$m' README.md"
done
chk "no removals from master in README" \
    "[ -z \"\$(git diff master -- README.md | grep '^-' | grep -v '^---')\" ]"
chk "no removals from master in Makefile" \
    "[ -z \"\$(git diff master -- Makefile | grep '^-' | grep -v '^---' | grep -v '^-[.]PHONY:')\" ]"

echo "== round 1: wrong -shm explanation gone =="
chk "README has no -shm claim"    "! grep -q 'shm' README.md"
chk "compose has no -shm claim"   "! grep -q 'shm' docker-compose.yml"
chk "no 'ordinary filesystem'"    "! grep -rq 'ordinary filesystem' README.md Makefile docker-compose.yml"
chk "cites locking_mode=EXCLUSIVE" "grep -q 'locking_mode=EXCLUSIVE' Makefile docker-compose.yml"

echo "== round 2 =="
chk "stack-test trap uses down -v"  "grep -q \"trap 'docker compose down -v' EXIT\" Makefile"
chk "stack-clean exists"            "grep -q '^stack-clean:' Makefile"
chk "assertion scoped to session"   "grep -q 'session_id=\$(DEMO_SESSION_ID)' Makefile"
chk "docker wait code checked"      "grep -q 'railmon.s demo exited' Makefile"
chk "clone has cleanup guard"       "grep -q 'rm -rf railmon; exit 1' Makefile"

echo "== round 3 =="
chk "webhook precondition guard"    "grep -q '^railmon-webhook-check:' Makefile"
chk "ref-drift guard"               "grep -q '^railmon-ref-check:' Makefile"
chk "stack depends on guard"        "grep -q '^stack: railmon-webhook-check' Makefile"
chk "stack-test depends on guard"   "grep -q '^stack-test: railmon-webhook-check' Makefile"
chk "clone resolves any ref"        "grep -q 'checkout --detach' Makefile"
chk "no --branch \$(RAILMON_REF)"   "! grep -q 'clone --depth 1 --branch' Makefile"
chk "ref stamp written"             "grep -q '.railmon-ref' Makefile"
chk "file_lines emptiness guard"    "grep -q 'capture.jsonl is empty' Makefile"
chk "asserts webhook delivered"     "grep -q 'webhook path did not deliver' Makefile"
chk "README states precondition"    "grep -q 'railmon/pull/9' README.md"
n=$(grep -c 'ok=0; for i in' Makefile)
if [ "$n" = "2" ]; then ok "both readiness loops guarded (found $n)"; else no "both readiness loops guarded (found $n, want 2)"; fi

echo "== guards actually fire (sandboxed copy, your ./railmon untouched) =="
t=$(mktemp -d); cp Makefile "$t/"; mkdir -p "$t/railmon/tools/local-demo"
printf '#!/bin/sh\n"$collector" --output x --comm python3\n' > "$t/railmon/tools/local-demo/run_local_demo.sh"
printf 'master\n' > "$t/railmon/.railmon-ref"
if ! make -C "$t" railmon-webhook-check RAILMON_REF=master >/dev/null 2>&1; then ok "webhook guard rejects a RailMon without the passthrough"
else no "webhook guard rejects a RailMon without the passthrough"; fi
printf 'RAILMON_WEBHOOK_URL\nRAILMON_SESSION_ID\n' >> "$t/railmon/tools/local-demo/run_local_demo.sh"
if make -C "$t" railmon-webhook-check RAILMON_REF=master >/dev/null 2>&1; then ok "webhook guard accepts one with it"
else no "webhook guard accepts one with it"; fi
if ! make -C "$t" railmon-ref-check RAILMON_REF=v0.1.0-m2 >/dev/null 2>&1; then ok "ref guard rejects a silent override"
else no "ref guard rejects a silent override"; fi
rm -rf "$t"

echo "== round 4 =="
chk "RAILMON_REF default is a SHA, not a branch" "grep -qE '^RAILMON_REF \?= [0-9a-f]{7,40}$' Makefile"
chk "stack-clean guards a foreign checkout"      "grep -q 'did not clone it' Makefile"
chk "stack-clean guards uncommitted work"        "grep -q 'uncommitted changes. Leaving it alone' Makefile"
chk "webhook check greps SESSION_ID too"         "grep -q 'grep -q RAILMON_SESSION_ID' Makefile"
chk "container id quoted"                        "grep -q 'docker wait \"' Makefile"
chk "exec failure not masked by a pipe"          "! grep -q 'cat /captures/capture.jsonl | wc -l' Makefile"
chk "assertions use parsed total"                "grep -q 'total=\$\$((inserted + duplicate))' Makefile"
n_commits=$(git rev-list --count master..HEAD 2>/dev/null || echo 0)
n_signed=$(git log master..HEAD --format='%(trailers:key=Signed-off-by)' 2>/dev/null | grep -c 'Signed-off-by' || true)
if [ "$n_commits" -gt 0 ] && [ "$n_commits" = "$n_signed" ]; then ok "all $n_commits commits signed off (DCO)"
else no "all commits signed off (DCO) -- $n_signed of $n_commits; run: git rebase --signoff master"; fi

echo "== stack-test assertion logic =="
c(){ [ "$1" -gt 0 ] && [ "$3" -eq "$1" ] && [ "$2" = "0" ] && [ "$4" -eq "$1" ]; }
c 6 0 6 6  && ok "both paths wired -> passes"          || no "both paths wired -> passes"
c 6 6 0 6  && no "webhook never fired -> fails"        || ok "webhook never fired -> fails"
c 0 0 0 0  && no "empty capture -> fails"              || ok "empty capture -> fails"
c 6 0 6 12 && no "dedup broken -> fails"               || ok "dedup broken -> fails"

echo
printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = "0" ] && echo "-> ready for /rail-review" || echo "-> fix the above first"
exit "$fail"
