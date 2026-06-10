#!/bin/bash
# CONFIDIS End-to-End Demo Script
# This script demonstrates the basic user workflow for public testnet:
# 1. Clean node setup
# 2. User wallet creation
# 3. Cellule creation
# 4. File upload and retrieval
# 5. Logs/evidence export

set -e

echo "=== CONFIDIS End-to-End Demo ==="
echo "This script will set up a clean CONFIDIS node and demonstrate the basic workflow."

# Configuration
NODE_PORT=4433
NODE_URL="http://127.0.0.1:$NODE_PORT"
WORK_DIR="/tmp/confidis-demo"
STORE_PATH="$WORK_DIR/store"
REGISTRY_PATH="$WORK_DIR/registry.json"
BLOB_STORE="$WORK_DIR/blobs"
CELLULE_KEY="$WORK_DIR/cellule.key"
UPLOAD_RECEIPT="$WORK_DIR/upload-receipt.json"
DEMO_FILE="$WORK_DIR/demo-data.txt"
DOWNLOAD_DIR="$WORK_DIR/downloaded"

# Clean up previous run
echo "Cleaning up previous demo..."
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$BLOB_STORE" "$DOWNLOAD_DIR"

# Create demo data file
echo "Creating demo data file..."
echo "This is confidential patient data for demo purposes.
Name: John Doe
Medical Record: Sample data
Date: $(date)" > "$DEMO_FILE"

# Build the project
echo "Building CONFIDIS..."
cargo build --release

# Generate keys
echo "Generating keys..."
# Generate owner key pair
WALLET_OUTPUT=$(./target/release/confidis wallet create)
OWNER_PRIVATE_KEY=$(echo "$WALLET_OUTPUT" | grep "private_key=" | cut -d'=' -f2)
OWNER_PUBLIC_KEY=$(echo "$WALLET_OUTPUT" | grep "public_key=" | cut -d'=' -f2)
OWNER_ADDRESS=$(echo "$WALLET_OUTPUT" | grep "wallet_address=" | cut -d'=' -f2)

echo "Owner public key: $OWNER_PUBLIC_KEY"

# Create node config
echo "Creating node config..."
NODE_CONFIG="$WORK_DIR/node-config.json"
./target/release/confidis node init-config \
    --node-id "demo-node-1" \
    --store-path "$STORE_PATH" \
    --registry-path "$REGISTRY_PATH" \
    --listen-addr "127.0.0.1:$NODE_PORT" \
    --max-bytes 1000000000 \
    --region "demo" \
    --failure-domain "demo-1" \
    --output "$NODE_CONFIG"

# Start node in background
echo "Starting CONFIDIS node..."
export RUST_LOG=info
./target/release/confidis node serve "$NODE_CONFIG" \
    > "$WORK_DIR/node.log" 2>&1 &
NODE_PID=$!

# Wait for node to start
echo "Waiting for node to start..."
sleep 5

# Check if node is running
if ! curl -s "$NODE_URL/health" > /dev/null; then
    echo "Node failed to start. Check logs:"
    cat "$WORK_DIR/node.log"
    exit 1
fi

echo "Node is running at $NODE_URL"

# Create cellule
echo "Creating cellule..."
CELLULE_NAME="demo-cellule"
CELLULE_EXPIRY=$(date -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)

./target/release/confidis cellule record \
    --name "$CELLULE_NAME" \
    --public-key "$OWNER_PUBLIC_KEY" \
    --private-key "$OWNER_PRIVATE_KEY" \
    --registry "$REGISTRY_PATH" \
    --blob-store "$BLOB_STORE" \
    --cellule-key "$CELLULE_KEY" \
    --expires-at "$CELLULE_EXPIRY" \
    --output "$WORK_DIR/cellule-receipt.json"

CELLULE_ID=$(./target/release/confidis cellule id --public-key "$OWNER_PUBLIC_KEY")
echo "Cellule created with ID: $CELLULE_ID"

# Upload file to cellule
echo "Uploading file to cellule..."
./target/release/confidis cellule put \
    --node "$NODE_URL" \
    --input "$DEMO_FILE" \
    --work-dir "$WORK_DIR/work" \
    --registry "$REGISTRY_PATH" \
    --blob-store "$BLOB_STORE" \
    --public-key "$OWNER_PUBLIC_KEY" \
    --private-key "$OWNER_PRIVATE_KEY" \
    --cellule-key "$CELLULE_KEY" \
    --expires-at "$CELLULE_EXPIRY" \
    --sequence 1 \
    --output "$UPLOAD_RECEIPT"

echo "File uploaded."

# Retrieve file from cellule
echo "Retrieving file from cellule..."
./target/release/confidis cellule get \
    --node "$NODE_URL" \
    --cellule-id "$CELLULE_ID" \
    --output-dir "$DOWNLOAD_DIR" \
    --registry "$REGISTRY_PATH" \
    --blob-store "$BLOB_STORE" \
    --private-key "$OWNER_PRIVATE_KEY" \
    --cellule-key "$CELLULE_KEY"

echo "File retrieved."

# Verify data
if diff "$DEMO_FILE" "$DOWNLOAD_DIR"/* > /dev/null; then
    echo "✓ Data integrity verified!"
else
    echo "✗ Data integrity check failed!"
    exit 1
fi

# Export logs/evidence
echo "Exporting security events..."
curl -s "$NODE_URL/compliance/security-events" > "$WORK_DIR/security-events.jsonl"

echo "Demo completed successfully!"
echo ""
echo "Evidence files:"
echo "- Security events: $WORK_DIR/security-events.jsonl"
echo "- Cellule receipt: $WORK_DIR/cellule-receipt.json"
echo "- Upload receipt: $WORK_DIR/upload-receipt.json"
echo ""
echo "To clean up: kill $NODE_PID && rm -rf $WORK_DIR"

# Keep node running for manual inspection
echo "Node is still running at $NODE_URL for manual inspection."
echo "Press Ctrl+C to stop."

# Wait for user
trap "echo 'Stopping node...'; kill $NODE_PID; exit 0" INT
wait $NODE_PID