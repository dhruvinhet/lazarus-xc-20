#!/bin/bash
# THE ONLY place where subject-related code is started, and the ONLY place that launches the trusted sandbox probe.
# usage: run-sandbox.sh <image> <container name> <historical.js|sandbox-probe.js> <host log file> <role: subject|probe> <status file>
#
# P0-1 fix (evidence separation): each role writes to its OWN host-created directory - out/ for the subject, probe-out/
# for the trusted probe. These are never the same directory and never both mounted into the same container, so subject
# code has no filesystem path into the probe's output, before, during, or after either container runs. The probe's
# directory must be empty before every probe launch: a pre-existing file there (for example, planted by a previous step)
# is refused rather than silently reused.
#
# Full lifecycle permission fix (independent review, rounds 2 and 3): the container always runs as uid 1000:1000, but
# the HOST steps (this script, and later validate-probe.js) run as whatever account GitHub assigned the job - real XA
# v1 evidence recorded that as uid 1001. Round 2 made probe-out/ writable by the container (chown 1000:1000, chmod
# 0700) but left it unreadable by the host afterward: mode 0700 owned by 1000 denies even traversal to uid 1001, so
# validate-probe.js's very first lstat failed - reported, before this round's error-reporting fix, as "vanished" instead
# of the real EACCES. Round 3 completes the lifecycle as an explicit, symmetric HANDOFF, restrictive at every step:
#   1. discover the real host identity (HOST_UID/HOST_GID) BEFORE touching anything, with id -u/-g - never hardcoded,
#      since the exact uid is runner-dependent and the point is to hand control back to whoever actually asked for it;
#   2. verify probe-out/ is a plain directory, never a symlink, before every privileged operation on it (see
#      assert_plain_dir below) - a symlink there could otherwise redirect a privileged chown/chmod to an arbitrary path;
#   3. hand the directory to uid 1000 (chown -h, so a symlink would be touched as itself rather than dereferenced) and
#      restrict it to mode 0700 - the container can now write, no one else (not even the host) can read it yet;
#   4. run the container;
#   5. unconditionally hand the directory BACK to the real host identity (same assert + chown -h + chmod 0700), whether
#      or not the container succeeded, so the next step (validate-probe.js, running as that same host identity) can
#      always at least attempt to read whatever is there. If the hand-back itself fails, that is recorded as its own
#      failure (handback_failed, distinct from the container's own exit_code) and a best-effort privileged cleanup
#      (sudo rm -rf) is attempted immediately, so a failure here can never leave a stuck, unreadable, unremovable
#      directory for a later unprivileged step to choke on. A probe whose output cannot be handed back is treated as a
#      failed probe: role=probe's own exit code is forced nonzero in that case, on top of whatever docker returned.
# Changing ownership to a uid the current step is not running as requires privilege, which is why this uses sudo;
# GitHub-hosted ubuntu-24.04 runners grant the default runner user passwordless sudo (the same v1 evidence recorded
# "sudo: AVAILABLE" directly on the host). sudo's own exit code is the fail-closed signal for every step: a root-level
# chown/chmod that reports success really did take effect, so no separate post-hoc stat re-check is layered on top
# (and such a check would not be portable - see the round-2 changelog). The real outcome, including the full
# write-then-handoff-then-read cycle, is verified independently on a real Linux filesystem in
# scripts/test-probe-permissions-linux.js.
#
# P0-2 fix (exit status honesty): this launcher used to always "exit 0", hiding every container failure, including a
# failed trusted security probe. It now records the REAL docker exit code (and whether a timeout killed it) into
# <status file>, a path OUTSIDE every container mount, so neither container can read or alter it, then:
#   - role=subject: tolerates a nonzero exit (a broken historical run is a legitimate experimental result) but still
#     records it honestly, so the workflow step itself does not fail the job because of an experiment's own outcome.
#   - role=probe: PROPAGATES the real exit code (or a forced failure if the hand-back above failed). A probe that
#     crashes, errors, times out, or cannot be handed back fails its own workflow step (and so the examine job), so
#     GitHub's job record reflects a failed security measurement rather than a silent one.
# validate-probe.js (run afterwards, also on the host) is what actually decides whether probe output becomes evidence;
# this script's only job is to never lie about what docker returned, and to leave that evidence somewhere the next
# trusted step can actually reach.
set -u
IMG="$1"; NAME="$2"; SCRIPT="$3"; LOG="$4"; ROLE="$5"; STATUS="$6"
DOCKER="${DOCKER_BIN:-docker}"   # overridable only for offline tests; the live workflow never sets DOCKER_BIN
case "$SCRIPT" in historical.js|sandbox-probe.js) ;; *) echo "run-sandbox: script not allowed: $SCRIPT" >&2; exit 2;; esac
case "$ROLE" in subject|probe) ;; *) echo "run-sandbox: role not allowed: $ROLE" >&2; exit 2;; esac
if [ "$ROLE" = subject ] && [ "$SCRIPT" != historical.js ]; then echo "run-sandbox: role subject may only run historical.js" >&2; exit 2; fi
if [ "$ROLE" = probe ] && [ "$SCRIPT" != sandbox-probe.js ]; then echo "run-sandbox: role probe may only run sandbox-probe.js" >&2; exit 2; fi
if [ -z "$LOG" ] || [ -z "$STATUS" ]; then echo "run-sandbox: log file and status file are required" >&2; exit 2; fi

# The real host identity, captured before anything below runs as anyone else. Never hardcoded: the exact uid/gid is
# runner-dependent (real XA v1 evidence showed 1001; it could legitimately be something else on a different runner).
HOST_UID="$(id -u)"; HOST_GID="$(id -g)"

OUTDIR="out"; [ "$ROLE" = probe ] && OUTDIR="probe-out"

# Refuses (exit 2) unless $1 is either absent or a genuine, non-symlink directory. Called before every privileged
# operation on $OUTDIR, including right after mkdir, as defense against a directory being replaced by a symlink
# between check and use. chown/chmod below also pass -h (no-dereference) as a second, independent layer: even if this
# check somehow raced, -h touches the link itself rather than silently operating on whatever it points to.
assert_plain_dir() {
  if [ -L "$1" ]; then echo "run-sandbox: $1 is a symbolic link; refusing to operate on it" >&2; exit 2; fi
  if [ -e "$1" ] && [ ! -d "$1" ]; then echo "run-sandbox: $1 exists and is not a directory; refusing" >&2; exit 2; fi
}

assert_plain_dir "$OUTDIR"
if [ "$ROLE" = probe ] && [ -e "$OUTDIR" ] && [ -n "$(find "$OUTDIR" -mindepth 1 2>/dev/null)" ]; then
  echo "run-sandbox: refusing to launch the trusted probe: $OUTDIR already has content (must be empty before every probe run)" >&2
  exit 2
fi
mkdir -p "$OUTDIR"
assert_plain_dir "$OUTDIR"

if [ "$ROLE" = probe ]; then
  if ! sudo -n chown -h 1000:1000 "$OUTDIR" 2>/dev/null || ! sudo -n chmod 0700 "$OUTDIR" 2>/dev/null; then
    echo "run-sandbox: could not provision $OUTDIR for uid 1000 (chown/chmod via sudo failed); refusing to launch the trusted probe without correct permissions" >&2
    exit 2
  fi
fi

timeout 1200 "$DOCKER" run --rm --name "$NAME" --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 512 --memory 3g -e HOME=/tmp/home -e GITHUB_REPOSITORY \
  -v "$PWD/snap:/snap:ro" -v "$PWD/trusted/tools:/tools:ro" -v "$PWD/$OUTDIR:/out" \
  "$IMG" node "/tools/$SCRIPT" > "$LOG" 2>&1
DC=$?
TIMED=false; [ "$DC" = 124 ] && TIMED=true

HANDBACK_FAILED=false
if [ "$ROLE" = probe ]; then
  # Hand probe-out/ back to the real host identity, unconditionally (even if the container itself failed), so the next
  # trusted step can always at least attempt to read whatever is there. Checked fresh: the directory must still be a
  # genuine directory, never a symlink, even at this later point.
  if [ -L "$OUTDIR" ] || { [ -e "$OUTDIR" ] && [ ! -d "$OUTDIR" ]; }; then
    echo "run-sandbox: $OUTDIR is no longer a plain directory after the container ran; refusing to hand it back" >&2
    HANDBACK_FAILED=true
  elif ! sudo -n chown -h "$HOST_UID:$HOST_GID" "$OUTDIR" 2>/dev/null || ! sudo -n chmod 0700 "$OUTDIR" 2>/dev/null; then
    echo "run-sandbox: could not hand $OUTDIR back to the host (uid=$HOST_UID gid=$HOST_GID) after the probe container exited" >&2
    HANDBACK_FAILED=true
  fi
  if [ "$HANDBACK_FAILED" = true ]; then
    # Best-effort only: do not let a failed cleanup attempt mask the real failure being reported above.
    sudo -n rm -rf "$OUTDIR" 2>/dev/null || true
  fi
fi

if [ "$HANDBACK_FAILED" = true ]; then
  printf '{"role":"%s","script":"%s","exit_code":%s,"timed_out":%s,"handback_failed":true}\n' "$ROLE" "$SCRIPT" "$DC" "$TIMED" > "$STATUS"
else
  printf '{"role":"%s","script":"%s","exit_code":%s,"timed_out":%s}\n' "$ROLE" "$SCRIPT" "$DC" "$TIMED" > "$STATUS"
fi

if [ "$ROLE" = probe ]; then
  [ "$HANDBACK_FAILED" = true ] && [ "$DC" = 0 ] && DC=1
  exit "$DC"
fi
exit 0
