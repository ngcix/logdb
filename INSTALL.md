# LogDB Installation Guide

This guide helps you install logdb module and skills for any AI provider.

## Overview

LogDB consists of:
1. **Python Module** — Core CLI tool for log analysis
2. **Two Skills** — Integration guides for AI providers
   - `logdb-make` — Database creation and config management
   - `logdb-query` — Search and analysis

## Installation Steps

### Step 1: Install Python Module

Choose one method:

#### Option A: From Release Wheel
```bash
pip install https://github.sec.samsung.net/cuong-nguyen/logdb/releases/download/release/logdb-1.0.0-py3-none-any.whl
```

#### Option B: From Source (Latest)
```bash
pip install git+https://github.sec.samsung.net/cuong-nguyen/logdb.git
```

#### Option C: Development Install
```bash
git clone https://github.sec.samsung.net/cuong-nguyen/logdb.git
cd logdb
pip install -e .
```

### Step 2: Initialize Configuration

```bash
logdb config init
```

This creates `~/.logdb/config/` with default configs for all log types:
- `~/.logdb/config/dumpstate.toml`
- `~/.logdb/config/pcap.toml`
- `~/.logdb/config/hci.toml`

### Step 3: Add Skills to Your AI Provider

Skills location varies by AI provider. Check your provider's documentation for the correct location.

#### Claude Code (VSCode Extension)
Skills location: `.claude/skills/` in your project root

```bash
# Download both skill files to your project:
.claude/skills/
├── logdb-make/
│   └── SKILL.md
└── logdb-query/
    └── SKILL.md
```

Skill file URLs:
- logdb-make: https://github.sec.samsung.net/cuong-nguyen/logdb/blob/main/.claude/skills/logdb-make/SKILL.md
- logdb-query: https://github.sec.samsung.net/cuong-nguyen/logdb/blob/main/.claude/skills/logdb-query/SKILL.md

#### Claude.ai (Web)
Skills location: Personal skill library (if supported by your plan)

Copy skill content from URLs above into your provider's skill creation interface.

#### Other AI Providers (Anthropic API, etc.)
Refer to your provider's documentation for:
- MCP tools location
- Function/tool integration
- External command execution

You can still use logdb via direct CLI calls without formal skill integration.

### Step 4: Verify Installation

```bash
# Check logdb CLI is available
logdb --help

# Check configs were created
ls ~/.logdb/config/

# Test with sample log
logdb config open -t dumpstate  # Edit if needed
logdb make -i sample.log -t dumpstate -o test.duckdb
logdb inspect test.duckdb
```

## Usage Pattern

### With Skills (Recommended for Claude Code)

```
User: "Analyze this dumpstate log for errors"
→ AI invokes logdb-make skill to import log
→ AI invokes logdb-query skill to search and analyze
→ Results returned as JSON
```

### Without Skills (Direct CLI)

```bash
# Import log
logdb make -i dumpstate.log -t dumpstate -o case.duckdb

# Search and analyze
logdb search case.duckdb -t dumpstate -c tag ERROR -r 50
logdb next case.duckdb -t dumpstate -l 1000 -r 10
logdb query case.duckdb "SELECT * FROM dumpstate WHERE level='E'"
```

## Provider-Specific Notes

### Claude Code (VSCode Extension)
- Skill files auto-discovered from `.claude/skills/`
- Full CLI integration with execution tracking
- JSON output parsing for structured results
- Environment variable support: `$LOGDB` for tool path

### Claude.ai Web
- Skills available if your plan supports it
- Copy skill content to your library
- Use as reference for manual operations

### Anthropic API (Direct)
- No built-in skill support
- Call logdb as subprocess or MCP tool
- Parse JSON output programmatically
- Example Python wrapper:
  ```python
  import subprocess
  import json
  
  result = subprocess.run(
    ["logdb", "search", "case.duckdb", "-t", "dumpstate", "-c", "tag", "ERROR"],
    capture_output=True, text=True
  )
  data = json.loads(result.stdout)
  ```

### Codeium, Copilot, etc.
- logdb available as CLI tool if installed
- No formal skill integration (provider-dependent)
- Reference skills for usage patterns
- Call via terminal/subprocess integration

## Configuration

### Centralized Config Location

All configs stored in `~/.logdb/config/`:
- No scattered `.toml` files in project directories
- Single config shared across all databases of same type
- Edit with: `logdb config open -t <type>`

### Customize Parsing

Edit config for your log format:

```bash
logdb config open -t dumpstate
# Update regex patterns, add/remove columns
# Save and re-run: logdb make -i log.txt -t dumpstate -o db.duckdb --force
```

## Troubleshooting

### "logdb command not found"
- Check installation: `pip list | grep logdb`
- If using virtual env, activate it first
- Update PATH or use full path: `python -m logdb`

### "Config not found"
- Run: `logdb config init` to create defaults
- Check location: `ls ~/.logdb/config/`

### "Table already exists"
- Use `--force` flag: `logdb make ... --force`
- Or delete database and recreate: `rm case.duckdb`

### "tshark not found" (PCAP)
- Install Wireshark: `apt-get install tshark` (Linux) or `brew install wireshark` (macOS)
- Ensure `tshark` is on PATH

### Skills not appearing in AI provider
- Verify skill file location matches provider's expectations
- Check file format: must be `.md` with frontmatter (`---name: ...---`)
- Refresh or restart provider application
- Check provider documentation for skill discovery

## Advanced Usage

### Loop Configs for Team
```bash
# Export config for sharing
cat ~/.logdb/config/dumpstate.toml

# Import on another machine
mkdir -p ~/.logdb/config
# Paste config into ~/.logdb/config/dumpstate.toml
```

### Batch Import Multiple Logs
```bash
for log in *.log; do
  logdb make -i "$log" -t dumpstate -o "${log%.log}.duckdb" --force
done
```

### Export Query Results
```bash
logdb query case.duckdb "SELECT * FROM dumpstate WHERE level='E'" | jq '.' > errors.json
```

## Support

For issues or questions:
- Check `.claude/skills/` for command examples
- Review skill documentation in SKILL.md files
- Check GitHub issues: https://github.sec.samsung.net/cuong-nguyen/logdb/issues
