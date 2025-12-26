# Blender Files Repository

A repository for managing Blender files (.blend) with security scanning to detect potentially malicious embedded scripts.

## Documentation

- [Manual (Japanese)](docs/manual.md) - Usage (Japanese)
- [Design Document (Japanese)](docs/design.md) - Design document (Japanese)

## Features

- Extract and analyze Python code embedded within Blender files
- Detect dangerous patterns (e.g., `os.system`, `subprocess`, `exec`)
- Warning-level detection for patterns like `eval()` used in legitimate scripts (e.g., Rigify)
- Integration with [bandit](https://bandit.readthedocs.io/) for enhanced security scanning

## Requirements

- Python 3.10+
- Blender (any version, default: blender-5)
- bandit (optional, for enhanced scanning)
- Git LFS (for .blend files)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd blender_files

# Create virtual environment and install dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
python scripts/scan_blend.py <blend_file>
```

### Options

```bash
# Show extracted script contents
python scripts/scan_blend.py <blend_file> --verbose

# Specify Blender version
python scripts/scan_blend.py <blend_file> -b blender-4-LTS

# Run with user addons enabled
python scripts/scan_blend.py <blend_file> --with-addons

# List available Blender versions
python scripts/scan_blend.py --list-versions

# Run specific scanners only
python scripts/scan_blend.py <blend_file> --scanners malware,privacy
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BLENDER_BASE_DIR` | Blender installation directory | `$HOME/Application/blender` |

### Example Output

```
Target file: assets/meshes/robot.blend
Blender version: blender-5
(Addons disabled)

Extracting scripts...
Extraction complete

==================================================
Blender Script Security Scanner
==================================================

[Detected Text Blocks]
  - rig_ui.py
  - custom_script.py

[Warning] Patterns requiring attention detected
(May be used in legitimate scripts like Rigify)

  rig_ui.py:1038: return eval(names_string)

[bandit Security Scan]
...

==================================================
Scan complete: Warnings found (review recommended)
```

### Exit Codes

| Code | Description |
|------|-------------|
| 0 | No issues or warnings only |
| 1 | Dangerous patterns detected |

## Pattern Detection

### Malware Scanner

**Error Level (Dangerous)** - These patterns will cause the scan to fail:

- `os.system`, `os.popen`
- `subprocess`
- `exec(`
- `socket.`
- `requests.`, `urllib.`
- `shutil.rmtree`
- `__import__`

**Warning Level** - These patterns require manual review:

- `eval(` - commonly used in Rigify and other legitimate addons

### Privacy Scanner

**Error Level** - Leaked secrets:

- API keys (OpenAI, GitHub, AWS, Slack)
- Hardcoded passwords
- Database connection strings
- Private keys

**Warning Level** - Personal information:

- User home paths (`/home/username/`, `C:\Users\username\`)
- Email addresses
- Token/secret variables

## License

MIT License - see [LICENSE](LICENSE) for details.
