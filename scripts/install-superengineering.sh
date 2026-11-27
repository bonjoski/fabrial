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
    if ! command -v sc >/dev/null 2>&1 && ! command -v se >/dev/null 2>&1; then
        echo "Error: 'sc' or 'se' CLI not found. super.engineering must be installed to configure global App Settings." >&2
        exit 1
    fi
    CLI_BIN="sc"
    if ! command -v sc >/dev/null 2>&1; then
        CLI_BIN="se"
    fi
    echo "  → Configuring global App Settings via '${CLI_BIN}' CLI (applies to ALL workspaces)..."
    
    # Prune deprecated legacy commands
    for dep in fabrial-doctor argus-audit airlock-status shield-status conjoiner-check stormcage-scan soulcaster-verify bomhound-enrich; do
        ${CLI_BIN} commands delete "${dep}" --scope global >/dev/null 2>&1 || true
    done

    ${CLI_BIN} commands create "stack-doctor" --command "fabrial doctor --fix" --provider none --scope global --icon "🩺" >/dev/null 2>&1 || true
    ${CLI_BIN} commands create "pre-flight" --command "argus vet --diff && soulcaster verify-patch -base HEAD" --provider none --scope global --icon "🛡️" >/dev/null 2>&1 || true
    ${CLI_BIN} project scripts set setup "fabrial doctor --fix" --scope user >/dev/null 2>&1 || true
    if command -v halfshard >/dev/null 2>&1; then
        ${CLI_BIN} project scripts set run halfshard "halfshard proxy --addr 127.0.0.1:8443 --tls" --scope user >/dev/null 2>&1 || true
    fi
    echo "✔ Successfully configured global App Settings for all paths and workspaces."
    exit 0
fi

CONFIG_DIR="${TARGET_DIR}/.super.engineering"
CONFIG_FILE="${CONFIG_DIR}/config.json"
mkdir -p "${CONFIG_DIR}"

python3 -c "
import json, os, shutil, uuid

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

# Ensure run (only add halfshard proxy run target when halfshard is installed on PATH)
if shutil.which('halfshard'):
    run = cfg.get('run', [])
    if not any(r.get('name') == 'halfshard' for r in run):
        run.append({
            'name': 'halfshard',
            'commands': ['halfshard proxy --addr 127.0.0.1:8443 --tls'],
            'default': False
        })
    cfg['run'] = run

# Ensure commands
cmds = cfg.get('commands', [])
deprecated = {'fabrial-doctor', 'argus-audit', 'airlock-status', 'shield-status', 'conjoiner-check', 'stormcage-scan', 'soulcaster-verify', 'bomhound-enrich'}
cmds = [c for c in cmds if c.get('name') not in deprecated]
existing_names = {c.get('name') for c in cmds}

defaults = [
    {'name': 'stack-doctor', 'command': 'fabrial doctor --fix', 'provider_preset_key': 'none', 'icon': '🩺'},
    {'name': 'pre-flight', 'command': 'argus vet --diff && soulcaster verify-patch -base HEAD', 'provider_preset_key': 'none', 'icon': '🛡️'},
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
