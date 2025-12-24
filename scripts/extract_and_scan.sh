#!/bin/bash
#
# Extract scripts from Blender files and run security scans
#
# Usage:
#   ./scripts/extract_and_scan.sh <blend_file>
#   ./scripts/extract_and_scan.sh <blend_file> [blender_version]
#
# Examples:
#   ./scripts/extract_and_scan.sh assets/meshes/robot.blend
#   ./scripts/extract_and_scan.sh assets/meshes/robot.blend blender-4-LTS
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLENDER_BASE_DIR="${BLENDER_BASE_DIR:-$HOME/Application/blender}"

# Default Blender version
DEFAULT_BLENDER_VERSION="blender-5"

# Disable addons (default: enabled)
# Set to 0 to load user addons
DISABLE_ADDONS="${DISABLE_ADDONS:-1}"

# Dangerous patterns (error level)
# exec\( detects only function calls (excludes execute method names)
DANGEROUS_PATTERNS="(os\.system|os\.popen|subprocess|exec\(|socket\.|requests\.|urllib\.|shutil\.rmtree|__import__)"

# Warning patterns (warning level)
# eval() may be used in legitimate scripts like Rigify
WARNING_PATTERNS="eval\("

# Colored output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <blend_file> [blender_version]"
    echo ""
    echo "Arguments:"
    echo "  blend_file       Target .blend file to scan"
    echo "  blender_version  Blender version to use (default: $DEFAULT_BLENDER_VERSION)"
    echo ""
    echo "Available Blender versions:"
    if [[ -d "$BLENDER_BASE_DIR" ]]; then
        ls -1 "$BLENDER_BASE_DIR" 2>/dev/null | grep -E "^blender-" || echo "  (not found)"
    else
        echo "  BLENDER_BASE_DIR does not exist: $BLENDER_BASE_DIR"
    fi
    exit 1
}

# Check arguments
if [[ $# -lt 1 ]]; then
    usage
fi

BLEND_FILE="$1"
BLENDER_VERSION="${2:-$DEFAULT_BLENDER_VERSION}"

# Check file exists
if [[ ! -f "$BLEND_FILE" ]]; then
    echo -e "${RED}Error: File not found: $BLEND_FILE${NC}"
    exit 1
fi

# Resolve Blender executable path
BLENDER_PATH="$BLENDER_BASE_DIR/$BLENDER_VERSION"
if [[ ! -x "$BLENDER_PATH" ]]; then
    echo -e "${RED}Error: Blender executable not found: $BLENDER_PATH${NC}"
    echo "Set BLENDER_BASE_DIR or specify the correct version"
    usage
fi

# Create temporary files
TEMP_DIR=$(mktemp -d)
EXTRACTED_SCRIPTS="$TEMP_DIR/extracted_scripts.txt"
trap "rm -rf $TEMP_DIR" EXIT

echo "=========================================="
echo "Blender Script Security Scanner"
echo "=========================================="
echo "Target file: $BLEND_FILE"
echo "Blender version: $BLENDER_VERSION"
echo "=========================================="
echo ""

# Step 1: Extract scripts
echo -e "${YELLOW}[1/3] Extracting scripts...${NC}"

# Build Blender command
BLENDER_OPTS="--background"
if [[ "$DISABLE_ADDONS" == "1" ]]; then
    BLENDER_OPTS="$BLENDER_OPTS --factory-startup"
    echo "(Addons disabled)"
fi

"$BLENDER_PATH" $BLENDER_OPTS "$BLEND_FILE" --python "$SCRIPT_DIR/extract_scripts.py" > "$EXTRACTED_SCRIPTS" 2>&1
BLENDER_EXIT=$?

# Check extraction success by looking for "Extraction Complete"
if ! grep -q "Extraction Complete" "$EXTRACTED_SCRIPTS"; then
    echo -e "${RED}Error: Script extraction failed${NC}"
    cat "$EXTRACTED_SCRIPTS"
    exit 1
fi

if [[ $BLENDER_EXIT -ne 0 ]]; then
    echo -e "${YELLOW}Note: Blender exited with warnings (exit code: $BLENDER_EXIT)${NC}"
fi

echo "Extraction complete"
echo ""

# Display extracted results
echo -e "${YELLOW}[2/3] Extracted scripts:${NC}"
echo "------------------------------------------"
cat "$EXTRACTED_SCRIPTS"
echo "------------------------------------------"
echo ""

# Step 2: Detect dangerous patterns
echo -e "${YELLOW}[3/3] Scanning for dangerous patterns...${NC}"
SCAN_RESULT=0
WARNING_FOUND=0

# Dangerous patterns (error level)
if grep -E "$DANGEROUS_PATTERNS" "$EXTRACTED_SCRIPTS" > /dev/null 2>&1; then
    echo -e "${RED}[Error] Dangerous patterns detected!${NC}"
    echo ""
    grep -n -E "$DANGEROUS_PATTERNS" "$EXTRACTED_SCRIPTS" || true
    echo ""
    SCAN_RESULT=1
fi

# Warning patterns (warning level)
if grep -E "$WARNING_PATTERNS" "$EXTRACTED_SCRIPTS" > /dev/null 2>&1; then
    echo -e "${YELLOW}[Warning] Patterns requiring attention detected${NC}"
    echo "(May be used in legitimate scripts like Rigify)"
    echo ""
    grep -n -E "$WARNING_PATTERNS" "$EXTRACTED_SCRIPTS" || true
    echo ""
    WARNING_FOUND=1
fi

if [[ $SCAN_RESULT -eq 0 ]] && [[ $WARNING_FOUND -eq 0 ]]; then
    echo -e "${GREEN}No dangerous patterns detected${NC}"
fi

echo ""

# Step 3: Scan with bandit (if installed)
if command -v bandit &> /dev/null; then
    echo -e "${YELLOW}[Additional] bandit security scan...${NC}"

    # Split into individual files per Text Block
    BANDIT_DIR="$TEMP_DIR/bandit_files"
    mkdir -p "$BANDIT_DIR"

    # Extract each Text Block and save to individual files
    current_block=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^"=== Text Block: "(.+)" ===" ]]; then
            current_block="${BASH_REMATCH[1]}"
            # Replace characters not allowed in filenames
            safe_name=$(echo "$current_block" | tr '/:' '__')
            echo "# Source: $current_block" > "$BANDIT_DIR/$safe_name"
        elif [[ "$line" =~ ^"===" ]]; then
            current_block=""
        elif [[ -n "$current_block" ]]; then
            safe_name=$(echo "$current_block" | tr '/:' '__')
            echo "$line" >> "$BANDIT_DIR/$safe_name"
        fi
    done < "$EXTRACTED_SCRIPTS"

    # Run bandit
    if ls "$BANDIT_DIR"/* &>/dev/null; then
        bandit -r "$BANDIT_DIR" 2>/dev/null || true
    else
        echo "No Python code to scan"
    fi
else
    echo -e "${YELLOW}Note: bandit is not installed${NC}"
    echo "Install: pip install bandit"
fi

echo ""
echo "=========================================="
if [[ $SCAN_RESULT -eq 1 ]]; then
    echo -e "${RED}Scan complete: Dangerous patterns detected${NC}"
    exit 1
elif [[ $WARNING_FOUND -eq 1 ]]; then
    echo -e "${YELLOW}Scan complete: Warnings found (review recommended)${NC}"
    exit 0
else
    echo -e "${GREEN}Scan complete: No issues found${NC}"
    exit 0
fi
