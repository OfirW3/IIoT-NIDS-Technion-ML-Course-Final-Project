#!/usr/bin/env bash
set -e

# Create the data directories in the project root (one level above bash_scripts)
BASE_DIR="../data"
PCAP_DIR="$BASE_DIR/pcaps"
RAW_DIR="$BASE_DIR/csvs"

mkdir -p "$PCAP_DIR" "$RAW_DIR"

echo "Created (or verified) directories:"
echo "  $PCAP_DIR"
echo "  $RAW_DIR"