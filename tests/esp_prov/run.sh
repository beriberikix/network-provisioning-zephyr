#!/usr/bin/env bash
# Drive the real esp_prov tool against the native_sim SoftAP DUT over a host
# Ethernet TAP (zeth), asserting the success and failure outcomes.
#
# Must run with CAP_NET_ADMIN to create the TAP. The easiest way with no root
# is a user+network namespace:
#
#   eval "$(tests/esp_prov/setup.sh /tmp/esp_prov_work)"
#   DUT_EXE=<build>/zephyr/zephyr.exe \
#     unshare -rn tests/esp_prov/run.sh
#
# Requires: ESP_PROV, IDF_PATH (from setup.sh) and DUT_EXE in the environment.
#
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

: "${DUT_EXE:?set DUT_EXE to the built native_sim zephyr.exe}"
: "${ESP_PROV:?set ESP_PROV (see setup.sh)}"
: "${IDF_PATH:?set IDF_PATH (see setup.sh)}"
PY="${PYTHON:-python3}"

DUT_IP=192.0.2.1
HOST_IP=192.0.2.2
POP=abcd1234
GOOD_SSID=HomeNet
GOOD_PASS=correct-horse-battery
LOG=$(mktemp)

cleanup() {
	[ -n "${DUT_PID:-}" ] && kill "$DUT_PID" 2>/dev/null
	ip link del zeth 2>/dev/null || true
	rm -f "$LOG"
}
trap cleanup EXIT

# Host side of the TAP the device attaches to.
ip tuntap add zeth mode tap
ip addr add "$HOST_IP/24" dev zeth
ip link set zeth up
ip link set lo up

"$DUT_EXE" >"$LOG" 2>&1 &
DUT_PID=$!

# Wait for the DUT to come up and answer on :80.
ready=0
for _ in $(seq 1 50); do
	if grep -q "DUT ready" "$LOG"; then
		ready=1
		break
	fi
	sleep 0.2
done
echo "=== DUT boot ==="
grep -iE 'host interface|SoftAP|Provisioning started|DUT ready' "$LOG" || true
if [ "$ready" != 1 ]; then
	echo "FAIL: DUT did not become ready"
	cat "$LOG"
	exit 1
fi

fail() { echo "FAIL: $1"; echo "--- esp_prov output ---"; cat "$2"; exit 1; }

run_prov() {  # <description> <expect-regex> <args...>
	local desc="$1" expect="$2"; shift 2
	local out; out=$(mktemp)
	echo "### $desc"
	# esp_prov exits 0 even for a reported provisioning failure, so the
	# outcome is asserted from its output, not its exit code.
	"$PY" "$ESP_PROV" --transport softap --service_name "$DUT_IP:80" \
		--sec_ver 1 --pop "$POP" "$@" >"$out" 2>&1 || true
	sed 's/^/    /' "$out"
	grep -qE "$expect" "$out" || fail "$desc: expected /$expect/" "$out"
	rm -f "$out"
}

run_prov "success (correct credentials)" "Provisioning was successful" \
	--ssid "$GOOD_SSID" --passphrase "$GOOD_PASS"
run_prov "wrong password -> Incorrect Password" "Incorrect Password" \
	--ssid "$GOOD_SSID" --passphrase wrongpassword123
run_prov "unknown SSID -> Incorrect SSID" "Incorrect SSID" \
	--ssid Ghost --passphrase whatever12345
# Custom application endpoint reached over the SoftAP fallback route: the DUT
# echoes "echo:<data>"; esp_prov prints the decrypted response.
run_prov "custom endpoint echo" "echo:hello-custom" \
	--ssid "$GOOD_SSID" --passphrase "$GOOD_PASS" --custom_data hello-custom

echo "PASS: esp_prov SoftAP scenarios all behaved as expected"
