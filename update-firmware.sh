#!/bin/bash

# Firmware Update Script for Dot-AT-Firmware repository
# Handles archives containing:
#   - mdot + xdot binaries
#   - xdotes + xdotad binaries

set -e
shopt -s nullglob  # Make globs return empty if no matches

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="/tmp/firmware-update-$$"

usage() {
    echo "Usage: $0 <archive.zip>"
    echo ""
    echo "Updates firmware binaries from a zip archive."
    echo "Supports archives containing:"
    echo "  - mdot and xdot binaries"
    echo "  - xdotes and xdotad binaries"
    echo ""
    echo "The script will:"
    echo "  1. Detect which firmware types are in the archive"
    echo "  2. Remove old versions of matching firmware"
    echo "  3. Copy new binaries to appropriate folders"
    exit 1
}

cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

# Check arguments
if [[ $# -ne 1 ]]; then
    usage
fi

ARCHIVE="$1"

# Expand ~ if present
ARCHIVE="${ARCHIVE/#\~/$HOME}"

if [[ ! -f "$ARCHIVE" ]]; then
    echo "Error: Archive not found: $ARCHIVE"
    exit 1
fi

echo "Extracting archive to temporary directory..."
mkdir -p "$TEMP_DIR"
unzip -q "$ARCHIVE" -d "$TEMP_DIR"

# Find the bins directory (may be nested under archive/)
BINS_DIR=$(find "$TEMP_DIR" -type d -name "bins" | head -1)
if [[ -z "$BINS_DIR" ]]; then
    # If no bins directory, use the temp directory itself
    BINS_DIR="$TEMP_DIR"
fi

echo "Found binaries in: $BINS_DIR"

# Detect firmware types in archive
HAS_MDOT=false
HAS_XDOT=false
HAS_XDOTES=false
HAS_XDOTAD=false

if find "$BINS_DIR" -name "mdot-firmware-*.bin" | grep -q .; then
    HAS_MDOT=true
    echo "Detected: MDOT firmware"
fi

if find "$BINS_DIR" -name "xdot-firmware-*.bin" | grep -q .; then
    HAS_XDOT=true
    echo "Detected: XDOT firmware"
fi

if find "$BINS_DIR" -name "xdotes-firmware-*.bin" | grep -q .; then
    HAS_XDOTES=true
    echo "Detected: XDOTES firmware"
fi

if find "$BINS_DIR" -name "xdotad-firmware-*.bin" | grep -q .; then
    HAS_XDOTAD=true
    echo "Detected: XDOTAD firmware"
fi

if ! $HAS_MDOT && ! $HAS_XDOT && ! $HAS_XDOTES && ! $HAS_XDOTAD; then
    echo "Error: No recognized firmware binaries found in archive"
    exit 1
fi

# Function to extract version from firmware filename
get_version() {
    local file="$1"
    local basename=$(basename "$file")
    # Extract version like 4.1.38 from filename
    echo "$basename" | grep -oP '\d+\.\d+\.\d+' | head -1
}

# Function to update firmware for a given type
update_firmware() {
    local fw_type="$1"        # mdot, xdot, xdotes, xdotad
    local dest_dir="$2"       # MDOT, XDOT, XDOTES, XDOTAD
    local apps_subdir="$3"    # mdot-apps, xdot-apps, etc. (optional)
    
    echo ""
    echo "========================================="
    echo "Updating $fw_type firmware in $dest_dir"
    echo "========================================="
    
    # Find a sample file to get the new version
    local sample_file=$(find "$BINS_DIR" -name "${fw_type}-firmware-*.bin" | head -1)
    if [[ -z "$sample_file" ]]; then
        echo "No $fw_type firmware files found"
        return
    fi
    
    local new_version=$(get_version "$sample_file")
    echo "New version: $new_version"
    
    local dest_path="$SCRIPT_DIR/$dest_dir"
    
    # Create destination directories if they don't exist
    mkdir -p "$dest_path"
    mkdir -p "$dest_path/DEBUG"
    mkdir -p "$dest_path/APPS"
    
    # Remove old firmware files (any version)
    echo "Removing old $fw_type firmware files..."
    
    # Remove main firmware (non-debug)
    local old_count=$(find "$dest_path" -maxdepth 1 -name "${fw_type}-firmware-*.bin" ! -name "*-debug.bin" 2>/dev/null | wc -l)
    if [[ $old_count -gt 0 ]]; then
        find "$dest_path" -maxdepth 1 -name "${fw_type}-firmware-*.bin" ! -name "*-debug.bin" -delete
        echo "  Removed $old_count main firmware files"
    fi
    
    # Remove debug firmware
    old_count=$(find "$dest_path/DEBUG" -name "${fw_type}-firmware-*-debug.bin" 2>/dev/null | wc -l)
    if [[ $old_count -gt 0 ]]; then
        find "$dest_path/DEBUG" -name "${fw_type}-firmware-*-debug.bin" -delete
        echo "  Removed $old_count debug firmware files"
    fi
    
    # Remove application firmware
    old_count=$(find "$dest_path/APPS" -name "${fw_type}-firmware-*-application*.bin" 2>/dev/null | wc -l)
    if [[ $old_count -gt 0 ]]; then
        find "$dest_path/APPS" -name "${fw_type}-firmware-*-application*.bin" -delete
        echo "  Removed $old_count application firmware files"
    fi
    
    # Copy new firmware files
    echo "Copying new $fw_type firmware files..."
    
    # Copy main firmware (from bins root, non-debug)
    local copy_count=0
    for f in "$BINS_DIR"/${fw_type}-firmware-*-mbed-os-*.bin; do
        if [[ -f "$f" ]] && [[ ! "$f" == *-debug.bin ]]; then
            cp "$f" "$dest_path/"
            copy_count=$((copy_count + 1))
        fi
    done
    # Also check for xdot-max32670 style names (for XDOTES/XDOTAD)
    for f in "$BINS_DIR"/${fw_type}-firmware-*-xdot-max32670.bin; do
        if [[ -f "$f" ]]; then
            cp "$f" "$dest_path/"
            copy_count=$((copy_count + 1))
        fi
    done
    echo "  Copied $copy_count main firmware files"
    
    # Copy debug firmware
    copy_count=0
    for f in "$BINS_DIR"/${fw_type}-firmware-*-debug.bin; do
        if [[ -f "$f" ]]; then
            cp "$f" "$dest_path/DEBUG/"
            copy_count=$((copy_count + 1))
        fi
    done
    # Check DEBUG subdirectory in source
    if [[ -d "$BINS_DIR/DEBUG" ]]; then
        for f in "$BINS_DIR/DEBUG"/${fw_type}-firmware-*-debug.bin; do
            if [[ -f "$f" ]]; then
                cp "$f" "$dest_path/DEBUG/"
                copy_count=$((copy_count + 1))
            fi
        done
    fi
    echo "  Copied $copy_count debug firmware files"
    
    # Copy application firmware
    copy_count=0
    local apps_src_dir=""
    
    # Check for apps subdirectory (mdot-apps, xdot-apps, etc.)
    if [[ -n "$apps_subdir" ]] && [[ -d "$BINS_DIR/$apps_subdir" ]]; then
        apps_src_dir="$BINS_DIR/$apps_subdir"
    elif [[ -d "$BINS_DIR/APPS" ]]; then
        apps_src_dir="$BINS_DIR/APPS"
    fi
    
    if [[ -n "$apps_src_dir" ]]; then
        for f in "$apps_src_dir"/${fw_type}-firmware-*-application*.bin; do
            if [[ -f "$f" ]]; then
                cp "$f" "$dest_path/APPS/"
                copy_count=$((copy_count + 1))
            fi
        done
    fi
    echo "  Copied $copy_count application firmware files"
}

# Update each detected firmware type
if $HAS_MDOT; then
    update_firmware "mdot" "MDOT" "mdot-apps"
fi

if $HAS_XDOT; then
    update_firmware "xdot" "XDOT" "xdot-apps"
fi

if $HAS_XDOTES; then
    update_firmware "xdotes" "XDOTES" "xdotes-apps"
fi

if $HAS_XDOTAD; then
    update_firmware "xdotad" "XDOTAD" "xdotad-apps"
fi

echo ""
echo "========================================="
echo "Firmware update complete!"
echo "========================================="
