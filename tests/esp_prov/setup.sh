#!/usr/bin/env bash
# Fetch the upstream esp_prov tool and generate the protobuf Python modules it
# needs, into a self-contained work directory. Prints shell `export` lines for
# ESP_PROV and IDF_PATH on stdout, so callers can `eval "$(setup.sh <dir>)"`.
#
# esp_prov loads pre-generated *_pb2.py from:
#   - $IDF_PATH/components/protocomm/python/   (constants/sec0/sec1/sec2/session)
#   - <esp_prov>/../../python/                 (network_constants/config/scan/ctrl)
# We regenerate all of them from .proto with the locally-installed protoc so the
# generated code matches the installed protobuf runtime (avoids version skew).
#
# SPDX-License-Identifier: Apache-2.0
set -eu

# Pinned upstream sources.
IDF_EXTRA_REF="${IDF_EXTRA_REF:-ff99b863787c14a73e25f122cde2557217fb31ef}"
IDF_PROTOCOMM_REF="${IDF_PROTOCOMM_REF:-v5.3.1}"
IDF_EXTRA_URL="https://github.com/espressif/idf-extra-components.git"
IDF_RAW="https://raw.githubusercontent.com/espressif/esp-idf/${IDF_PROTOCOMM_REF}/components/protocomm/proto"

WORK="${1:?usage: setup.sh <work-dir>}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

log() { echo "[esp_prov setup] $*" >&2; }

# 1. esp_prov tool + network_provisioning protos/python (pinned). Always check
# out the pinned ref, so re-running against an existing work dir is
# deterministic rather than silently reusing a stale checkout.
REPO_DIR="$WORK/idf-extra-components"
if [ ! -d "$REPO_DIR/.git" ]; then
	log "cloning idf-extra-components"
	git clone --filter=blob:none --sparse "$IDF_EXTRA_URL" "$REPO_DIR" >&2
	git -C "$REPO_DIR" sparse-checkout set \
		network_provisioning/tool/esp_prov network_provisioning/python \
		network_provisioning/proto >&2
fi
log "checking out ${IDF_EXTRA_REF}"
git -C "$REPO_DIR" fetch -q --filter=blob:none origin "${IDF_EXTRA_REF}" 2>/dev/null || true
git -C "$REPO_DIR" checkout -q "${IDF_EXTRA_REF}" >&2
NETPROV="$REPO_DIR/network_provisioning"

# 2. protocomm .proto (pinned esp-idf), for the security/session messages.
mkdir -p "$WORK/protocomm_proto"
for f in constants sec0 sec1 sec2 session; do
	[ -f "$WORK/protocomm_proto/$f.proto" ] || \
		curl -fsSL "$IDF_RAW/$f.proto" -o "$WORK/protocomm_proto/$f.proto"
done

# 3. Generate _pb2.py with the local protoc.
PCPY="$WORK/idf_stub/components/protocomm/python"
mkdir -p "$PCPY"
log "generating protobuf modules"
python3 -m grpc_tools.protoc -I"$WORK/protocomm_proto" --python_out="$PCPY" \
	constants.proto sec0.proto sec1.proto sec2.proto session.proto
python3 -m grpc_tools.protoc -I"$NETPROV/proto" -I"$WORK/protocomm_proto" \
	--python_out="$NETPROV/python" \
	network_constants.proto network_config.proto network_scan.proto network_ctrl.proto

echo "export ESP_PROV=\"$NETPROV/tool/esp_prov/esp_prov.py\""
echo "export IDF_PATH=\"$WORK/idf_stub\""
