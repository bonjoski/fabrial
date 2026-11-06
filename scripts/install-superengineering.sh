#!/usr/bin/env bash
# ==============================================================================
# install-superengineering.sh
#
# Bootstrap the Bonjoski Sovereign AI Agent Security Fabric into super.engineering
#
# Usage:
#   ./scripts/install-superengineering.sh [--global] [TARGET_DIR]
#   curl -fsSL https://raw.githubusercontent.com/bonjoski/fabrial/main/scripts/install-superengineering.sh | bash -s -- --global
# ==============================================================================

set -euo pipefail

IS_GLOBAL=false
TARGET_DIR="."

for arg in "$@"; do
    case "$arg" in
        --global|-g)
            IS_GLOBAL=true
            ;;
        *)
            if [[ ! "$arg" =~ ^- ]]; then
                TARGET_DIR="$arg"
            fi
            ;;
    esac
done

echo "💎 Initializing Bonjoski Sovereign Security Fabric for super.engineering..."

# If fabrial is installed and supports integrate, delegate to native CLI
if command -v fabrial >/dev/null 2>&1 && fabrial --help 2>&1 | grep -q "integrate"; then
    if [ "$IS_GLOBAL" = true ]; then
        fabrial integrate superengineering --global
    else
        fabrial integrate superengineering "${TARGET_DIR}"
    fi
    exit 0
fi

# Fallback: standalone initialization when fabrial CLI does not yet have 'integrate'
if [ "$IS_GLOBAL" = true ]; then
    if ! command -v sc >/dev/null 2>&1; then
        echo "Error: 'sc' CLI not found. super.engineering must be installed to configure global App Settings." >&2
        exit 1
    fi
    echo "  → Configuring global App Settings via 'sc' CLI (applies to ALL workspaces)..."
    sc commands create "fabrial-doctor" --command "fabrial doctor --fix" --provider none --scope global --icon "💎" >/dev/null 2>&1 || true
    sc commands create "argus-audit" --command "argus vet --diff" --provider none --scope global --icon "👁️" >/dev/null 2>&1 || true
    sc commands create "airlock-status" --command "airlock doctor --fix" --provider none --scope global --icon "🔒" >/dev/null 2>&1 || true
    sc commands create "shield-status" --command "shield status" --provider none --scope global --icon "🛡️" >/dev/null 2>&1 || true
    sc commands create "conjoiner-check" --command "fabrial session list" --provider none --scope global --icon "🔗" >/dev/null 2>&1 || true
    sc commands create "stormcage-scan" --command "stormcage scan" --provider none --scope global --icon "⚡" >/dev/null 2>&1 || true
    sc commands create "soulcaster-verify" --command "soulcaster verify-patch -base HEAD" --provider none --scope global --icon "🔮" >/dev/null 2>&1 || true
    sc commands create "bomhound-enrich" --command "bomhound ." --provider none --scope global --icon "🐾" >/dev/null 2>&1 || true
    sc project scripts set setup "fabrial doctor --fix" --scope user >/dev/null 2>&1 || true
    sc project scripts set run shield "shield proxy --addr 127.0.0.1:8443 --tls" --scope user >/dev/null 2>&1 || true
    echo "✔ Successfully configured global App Settings for all paths and workspaces."
    exit 0
fi

CONFIG_DIR="${TARGET_DIR}/.super.engineering"
CONFIG_FILE="${CONFIG_DIR}/config.json"
mkdir -p "${CONFIG_DIR}"

python3 -c "
import json, os, uuid

path = '${CONFIG_FILE}'
cfg = {}
if os.path.exists(path):
    try:
        with open(path, 'r') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

# Ensure setup
setup = cfg.get('setup', [])
if 'fabrial doctor' not in setup:
    setup.append('fabrial doctor')
cfg['setup'] = setup

# Ensure run
run = cfg.get('run', [])
if not any(r.get('name') == 'shield' for r in run):
    run.append({
        'name': 'shield',
        'commands': ['shield proxy --addr 127.0.0.1:8443 --tls'],
        'default': False
    })
cfg['run'] = run

# Ensure commands
cmds = cfg.get('commands', [])
existing_names = {c.get('name') for c in cmds}

defaults = [
    {'name': 'fabrial-doctor', 'command': 'fabrial doctor --fix', 'provider_preset_key': 'none', 'icon': '💎'},
    {'name': 'argus-audit', 'command': 'argus vet --diff', 'provider_preset_key': 'none', 'icon': '👁️'},
    {'name': 'airlock-status', 'command': 'airlock doctor --fix', 'provider_preset_key': 'none', 'icon': '🔒'},
    {'name': 'shield-status', 'command': 'shield status', 'provider_preset_key': 'none', 'icon': '🛡️'},
    {'name': 'conjoiner-check', 'command': 'fabrial session list', 'provider_preset_key': 'none', 'icon': '🔗'},
    {'name': 'stormcage-scan', 'command': 'stormcage scan', 'provider_preset_key': 'none', 'icon': '⚡'},
    {'name': 'soulcaster-verify', 'command': 'soulcaster verify-patch -base HEAD', 'provider_preset_key': 'none', 'icon': '🔮'},
    {'name': 'bomhound-enrich', 'command': 'bomhound .', 'provider_preset_key': 'none', 'icon': '🐾'},
]

for d in defaults:
    if d['name'] not in existing_names:
        cmd_obj = {
            'id': str(uuid.uuid4()),
            'name': d['name'],
            'command': d['command'],
            'dispatch_mode': 'inject_current_chat',
            'view_preference': 'default',
            'icon': d.get('icon', '⚡'),
            'auto_submit': True
        }
        if 'provider_preset_key' in d:
            cmd_obj['provider_preset_key'] = d['provider_preset_key']
        cmds.append(cmd_obj)

cfg['commands'] = cmds

with open(path, 'w') as f:
    json.dump(cfg, f, indent=2)
    f.write('\n')
"

echo "✔ Successfully generated ${CONFIG_FILE}"

if command -v sc >/dev/null 2>&1; then
    (cd "${TARGET_DIR}" && sc project scripts check >/dev/null 2>&1 || true)
fi

echo ""
echo "👉 Ensure fabrial is installed via Homebrew to execute security commands:"
echo "   brew install bonjoski/tap/fabrial"
