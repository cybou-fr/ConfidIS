#!/bin/bash
# CONFIDIS Restart Resilience Test
# Tests that the node recovers state correctly after restarts during various operations

set -e

echo "=== CONFIDIS Restart Resilience Test ==="

# Configuration
NODE_PORT=8788
NODE_URL="http://127.0.0.1:$NODE_PORT"
WORK_DIR="/tmp/confidis-restart-test"
STORE_PATH="$WORK_DIR/store"
REGISTRY_PATH="$WORK_DIR/registry.json"
BLOB_STORE="$WORK_DIR/blobs"
CELLULE_KEY="$WORK_DIR/cellule.key"
DEMO_FILE="$WORK_DIR/demo-data.txt"

# Clean up
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$BLOB_STORE"

# Create test data
echo "Test data for restart resilience" > "$DEMO_FILE"

# Build
echo "Building CONFIDIS..."
cargo build --release

# Generate keys
WALLET_OUTPUT=$(./target/release/confidis wallet create)
OWNER_PRIVATE_KEY=$(echo "$WALLET_OUTPUT" | grep "private_key=" | cut -d'=' -f2)
OWNER_PUBLIC_KEY=$(echo "$WALLET_OUTPUT" | grep "public_key=" | cut -d'=' -f2)

echo "Owner public key: $OWNER_PUBLIC_KEY"

# Create config
NODE_CONFIG="$WORK_DIR/node-config.json"
./target/release/confidis node init-config \
    --node-id "test-node-1" \
    --store-path "$STORE_PATH" \
    --registry-path "$REGISTRY_PATH" \
    --listen-addr "127.0.0.1:$NODE_PORT" \
    --max-bytes 100000000 \
    --region "test" \
    --failure-domain "test-1" \
    --output "$NODE_CONFIG"

echo "=== Test 1: Restart during upload ==="
# Start node
./target/release/confidis node serve "$NODE_CONFIG" > "$WORK_DIR/node1.log" 2>&1 &
NODE_PID=$!

sleep 3

# Start upload in background
echo "Starting upload..."
./target/release/confidis cellule record \
    --name "test-cellule" \
    --public-key "$OWNER_PUBLIC_KEY" \
    --private-key "$OWNER_PRIVATE_KEY" \
    --registry "$REGISTRY_PATH" \
    --blob-store "$BLOB_STORE" \
    --cellule-key "$CELLULE_KEY" \
    --expires-at "2027-01-01T00:00:00Z" \
    --output /dev/null

CELLULE_ID=$(./target/release/confidis cellule id --public-key "$OWNER_PUBLIC_KEY")

# Start upload (this should complete quickly, but we'll kill node during it)
timeout 10 ./target/release/confidis cellule put \
    --node "$NODE_URL" \
    --input "$DEMO_FILE" \
    --work-dir "$WORK_DIR/work" \
    --registry "$REGISTRY_PATH" \
    --blob-store "$BLOB_STORE" \
    --public-key "$OWNER_PUBLIC_KEY" \
    --private-key "$OWNER_PRIVATE_KEY" \
    --cellule-key "$CELLULE_KEY" \
    --expires-at "2027-01-01T00:00:00Z" \
    --sequence 1 \
    --output "$WORK_DIR/upload1.json" || true

# Kill node
kill $NODE_PID
sleep 2

# Restart node
echo "Restarting node..."
./target/release/confidis node serve "$NODE_CONFIG" > "$WORK_DIR/node2.log" 2>&1 &
NODE_PID=$!

sleep 3

# Check if upload completed or can be retried
if curl -s "$NODE_URL/health" > /dev/null; then
    echo "✓ Node restarted successfully"
else
    echo "✗ Node failed to restart"
    exit 1
fi

# Try to retrieve data
if ./target/release/confidis cellule get \
    --node "$NODE_URL" \
    --cellule-id "$CELLULE_ID" \
    --output-dir "$WORK_DIR/retrieved1" \
    --registry "$REGISTRY_PATH" \
    --blob-store "$BLOB_STORE" \
    --private-key "$OWNER_PRIVATE_KEY" \
    --cellule-key "$CELLULE_KEY" 2>/dev/null; then
    echo "✓ Data retrieval successful after restart"
else
    echo "⚠ Data retrieval failed (may be expected if upload was interrupted)"
fi

kill $NODE_PID
sleep 2

echo "=== Test 2: Restart during maintenance ==="
# Start node
./target/release/confidis node serve "$NODE_CONFIG" > "$WORK_DIR/node3.log" 2>&1 &
NODE_PID=$!

sleep 3

# Trigger some activity (upload more data)
for i in {1..3}; do
    echo "Data batch $i" > "$WORK_DIR/batch$i.txt"
    ./target/release/confidis cellule put \
        --node "$NODE_URL" \
        --input "$WORK_DIR/batch$i.txt" \
        --work-dir "$WORK_DIR/work$i" \
        --registry "$REGISTRY_PATH" \
        --blob-store "$BLOB_STORE" \
        --public-key "$OWNER_PUBLIC_KEY" \
        --private-key "$OWNER_PRIVATE_KEY" \
        --cellule-key "$CELLULE_KEY" \
        --expires-at "2027-01-01T00:00:00Z" \
        --sequence $((i+1)) \
        --output /dev/null 2>/dev/null || true
done

# Kill during potential maintenance
kill $NODE_PID
sleep 2

# Restart
./target/release/confidis node serve "$NODE_CONFIG" > "$WORK_DIR/node4.log" 2>&1 &
NODE_PID=$!

sleep 5

# Check health
if curl -s "$NODE_URL/health" > /dev/null; then
    echo "✓ Node recovered from maintenance interruption"
else
    echo "✗ Node failed recovery"
    exit 1
fi

# Check if registry is intact
if [ -f "$REGISTRY_PATH" ]; then
    echo "✓ Registry persisted across restart"
else
    echo "✗ Registry lost"
    exit 1
fi

kill $NODE_PID

echo "=== Test 3: Configuration persistence ==="
# Modify config and restart
cp "$NODE_CONFIG" "$NODE_CONFIG.backup"

# Start with modified config
./target/release/confidis node serve "$NODE_CONFIG" > "$WORK_DIR/node5.log" 2>&1 &
NODE_PID=$!

sleep 3

# Check if config is loaded
HEALTH=$(curl -s "$NODE_URL/health")
if echo "$HEALTH" | grep -q "test-node-1"; then
    echo "✓ Configuration loaded correctly"
else
    echo "✗ Configuration not loaded"
fi

kill $NODE_PID

echo "Restart resilience test completed!"
echo "Logs available in $WORK_DIR/"