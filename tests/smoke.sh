#!/usr/bin/env bash
# End-to-end smoke test: signed baseline, offline-change detection, live inotify
# events, and tamper detection on both the baseline and the hash-chained log.
set -u
FIMD="${1:-$(dirname "$0")/../build/fimd}"
T="$(mktemp -d)"
trap '[ -n "$WPID" ] && kill "$WPID" 2>/dev/null; rm -rf "$T"' EXIT
WPID=
pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
expect_rc() { # desc want cmd...
  local d="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1; local rc=$?
  [ "$rc" -eq "$want" ] && ok "$d" || bad "$d (rc=$rc, want $want)"
}

mkdir -p "$T/tree/sub" "$T/keys"
echo alpha > "$T/tree/a.txt"
echo beta  > "$T/tree/sub/b.txt"
printf 'weird\tname\n' > "$T/tree/$(printf 'we\tird')"
ln -s a.txt "$T/tree/link"

echo "== keys and baseline"
expect_rc "keygen"            0 "$FIMD" keygen --priv "$T/keys/k.pem" --pub "$T/keys/k.pub"
expect_rc "keygen refuses overwrite" 2 "$FIMD" keygen --priv "$T/keys/k.pem" --pub "$T/keys/k.pub"
[ "$(stat -c %a "$T/keys/k.pem")" = 600 ] && ok "private key is 0600" || bad "private key mode"
expect_rc "init"              0 "$FIMD" init -w "$T/tree" --baseline "$T/base" --key "$T/keys/k.pem"
expect_rc "check clean"       0 "$FIMD" check --baseline "$T/base" --pub "$T/keys/k.pub"

echo "== offline changes detected by check"
echo gamma >> "$T/tree/a.txt"
rm "$T/tree/sub/b.txt"
echo new > "$T/tree/c.txt"
chmod 600 "$T/tree/link" 2>/dev/null
out="$("$FIMD" check --baseline "$T/base" --pub "$T/keys/k.pub" 2>/dev/null)"; rc=$?
[ $rc -eq 1 ] && ok "check exits 1 on drift" || bad "check rc=$rc"
for k in MODIFIED DELETED ADDED; do
  echo "$out" | grep -q "$k" && ok "check reports $k" || bad "check missing $k"
done

echo "== baseline tampering"
cp "$T/base" "$T/base.bak"
sed -i 's/^created.*/created\t2000-01-01T00:00:00.000Z/' "$T/base"
expect_rc "edited baseline rejected" 2 "$FIMD" check --baseline "$T/base" --pub "$T/keys/k.pub"
cp "$T/base.bak" "$T/base"
"$FIMD" keygen --priv "$T/keys/o.pem" --pub "$T/keys/o.pub" 2>/dev/null
expect_rc "wrong public key rejected" 2 "$FIMD" check --baseline "$T/base" --pub "$T/keys/o.pub"

echo "== live watch"
# Re-baseline so the tree is clean, then watch with a log.
"$FIMD" init -w "$T/tree" --baseline "$T/base" --key "$T/keys/k.pem" 2>/dev/null
"$FIMD" watch --baseline "$T/base" --pub "$T/keys/k.pub" --log "$T/log" --debounce 100 >"$T/watch.out" 2>"$T/watch.err" &
WPID=$!
sleep 0.8
echo more >> "$T/tree/a.txt"                 # MODIFIED
echo fresh > "$T/tree/sub/new.txt"           # ADDED
rm "$T/tree/c.txt"                           # DELETED
chmod 700 "$T/tree/sub/new.txt"              # ATTRIB (after ADDED settles)
mkdir -p "$T/tree/deep/er"                   # new directory, then a file inside it
sleep 0.5
echo inner > "$T/tree/deep/er/inner.txt"     # must be seen via the freshly added watch
sleep 0.5                                    # let it settle: events are state diffs after the debounce,
                                             # so create-then-vanish inside one window nets to nothing
mv "$T/tree/deep" "$T/tree/moved"            # directory rename: DELETED old + ADDED new
sleep 1.0
kill -TERM "$WPID"; wait "$WPID" 2>/dev/null; WPID=

for pat in "MODIFIED .*/a.txt" "ADDED .*/sub/new.txt" "DELETED .*/c.txt" \
           "ADDED .*/deep/er/inner.txt" "DELETED .*/deep/er/inner.txt" "ADDED .*/moved/er/inner.txt"; do
  grep -Eq "$pat" "$T/watch.out" && ok "watch saw: $pat" || bad "watch missed: $pat"
done
grep -q "START" "$T/log" && grep -q "STOP" "$T/log" && ok "log has START and STOP markers" || bad "log markers"

echo "== log integrity"
expect_rc "verify-log clean"  0 "$FIMD" verify-log --log "$T/log"
headout="$("$FIMD" head --log "$T/log")"; head="${headout##*head=}"
[ "${#head}" -eq 64 ] && ok "head parsed as 64 hex chars" || bad "head parse: '$headout'"
expect_rc "verify-log with expected head" 0 "$FIMD" verify-log --log "$T/log" --expect-head "$head"

cp "$T/log" "$T/log.bak"
n="$(wc -l < "$T/log.bak")"
# edit a record body
awk 'BEGIN{FS=OFS="\t"} NR==2{$4=$4 "x"} {print}' "$T/log.bak" > "$T/log"
expect_rc "edited record detected" 1 "$FIMD" verify-log --log "$T/log"
# delete a middle record
sed '3d' "$T/log.bak" > "$T/log"
expect_rc "deleted record detected" 1 "$FIMD" verify-log --log "$T/log"
# swap two records
awk 'NR==2{a=$0;next} NR==3{print;print a;next} {print}' "$T/log.bak" > "$T/log"
expect_rc "reordered records detected" 1 "$FIMD" verify-log --log "$T/log"
# truncate tail: chain is self-consistent, only the external anchor catches it
head -n $((n-1)) "$T/log.bak" > "$T/log"
expect_rc "truncated tail passes bare verify" 0 "$FIMD" verify-log --log "$T/log"
expect_rc "truncated tail caught by --expect-head" 1 "$FIMD" verify-log --log "$T/log" --expect-head "$head"
cp "$T/log.bak" "$T/log"
expect_rc "daemon refuses to extend a broken log" 2 \
  bash -c "sed '3d' '$T/log.bak' > '$T/log'; '$FIMD' check --baseline '$T/base' --pub '$T/keys/k.pub' --log '$T/log'"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]
