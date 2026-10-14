#!/usr/bin/env bash
# tools/mutate_uci_read_pacing.sh -- break the BACKEND=uci read-pacing rule
# in the source, one mutant at a time; rebuild (make BACKEND=uci, in build/:
# it OVERWRITES the current build) and require tools/check_uci_read_pacing.py
# to go red (exit 1) on each. The source is restored after every mutant.
# Exit 0 only if every mutant is killed and the control passes.
cd "$(dirname "$0")/.." || exit 1
fails=0
mut() {  # name file old new
  python3 - "$2" "$3" "$4" <<'PY' || { echo "BROKEN $1"; fails=1; return; }
import sys
f, old, new = sys.argv[1], sys.argv[2].encode().decode("unicode_escape"), sys.argv[3].encode().decode("unicode_escape")
s = open(f).read(); assert s.count(old) == 1, (f, old, s.count(old)); open(f + ".orig", "w").write(s); open(f, "w").write(s.replace(old, new))
PY
  rm -rf build; make BACKEND=uci >build-mutant.log 2>&1 || { echo "BROKEN $1 (build)"; fails=1; mv "$2.orig" "$2"; return; }
  rm -f build-mutant.log
  out=$(python3 tools/check_uci_read_pacing.py 2>&1); rc=$?
  mv "$2.orig" "$2"
  if [ $rc -eq 1 ]; then echo "KILLED   $1: $(echo "$out" | grep -m1 FAIL | cut -c1-120)"; else echo "SURVIVED $1 (rc=$rc)"; fails=1; fi
}
mut put-unfenced src/net/uci/uci_cmd.s "uci_put_byte:\n        sta UCI_CMD_DATA\n        uci_fence\n" "uci_put_byte:\n        sta UCI_CMD_DATA\n"
mut begin-unfenced src/net/uci/uci_cmd.s "uci_begin_cmd:\n        sta UCI_CMD_DATA\n        uci_fence\n" "uci_begin_cmd:\n        sta UCI_CMD_DATA\n"
mut copy-read-fenced src/net/uci/net.s "        lda UCI_RESP_DATA\n        uci_read_fence                   ; settle before storing data byte" "        lda UCI_RESP_DATA\n        uci_fence"
mut status-wait-fenced src/net/uci/uci_cmd.s "@wr_loop:\n        lda UCI_STATUS\n        uci_read_fence" "@wr_loop:\n        lda UCI_STATUS\n        uci_fence"
mut statline-fenced src/net/uci/uci_cmd.s "        lda UCI_STATUS_DATA\n.ifdef UCI_READ_FENCE\n        jsr uci_settle\n.endif" "        lda UCI_STATUS_DATA\n        jsr uci_settle"
rm -rf build; make BACKEND=uci >/dev/null 2>&1
python3 tools/check_uci_read_pacing.py >/dev/null || fails=1
echo "control $(shasum -a 256 build/c64-https.prg | cut -c1-8): $(python3 tools/check_uci_read_pacing.py | tail -1)"
exit $fails
