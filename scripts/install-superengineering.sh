#!/usr/bin/env bash
# ==============================================================================
# install-superengineering.sh
#
# Bootstrap the Bonjoski Sovereign AI Agent Security Fabric into super.engineering
#
# Usage:
#   ./scripts/install-superengineering.sh [TARGET_DIR]
#   curl -fsSL https://raw.githubusercontent.com/bonjoski/fabrial/main/scripts/install-superengineering.sh | bash
# ==============================================================================

set -euo pipefail

TARGET_DIR="${1:-.}"
CONFIG_DIR="${TARGET_DIR}/.super.engineering"
CONFIG_FILE="${CONFIG_DIR}/config.json"

echo "💎 Initializing Bonjoski Sovereign Security Fabric for super.engineering..."

# If fabrial is installed and supports integrate, delegate to native CLI
if command -v fabrial >/dev/null 2>&1 && fabrial --help 2>&1 | grep -q "integrate"; then
    fabrial integrate superengineering "${TARGET_DIR}"
    exit 0
fi

# Fallback: standalone initialization when fabrial CLI does not yet have 'integrate'
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
        'commands': ['shield proxy --port 8080'],
        'default': False
    })
cfg['run'] = run

# Ensure commands
cmds = cfg.get('commands', [])
existing_names = {c.get('name') for c in cmds}

defaults = [
    {'name': 'fabrial-doctor', 'command': 'fabrial doctor', 'provider_preset_key': 'none', 'icon': '💎'},
    {'name': 'argus-audit', 'command': 'argus scan .', 'provider_preset_key': 'none', 'icon': '👁️'},
    {'name': 'airlock-status', 'command': 'airlock status', 'provider_preset_key': 'none', 'icon': '🔒'},
    {'name': 'shield-status', 'command': 'shield status', 'provider_preset_key': 'none', 'icon': '🛡️'},
    {'name': 'conjoiner-check', 'command': 'conjoiner version', 'provider_preset_key': 'none', 'icon': '🔗'},
    {'name': 'security-audit', 'command': 'Run an adversarial security review on recent changes using the adversarial-sentinel guidelines, checking for sandbox escapes, secrets leakage, and fail-open vulnerabilities.', 'icon': '⚔️'},
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
