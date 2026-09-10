#!/system/bin/sh
# One-shot fix: stop all daemon-relay + relay, replace with new version (no kill logic), restart a single daemon
set -x

echo "=== 1. Stop all daemon-relay ==="
for pid in $(pgrep -f daemon-relay); do
  [ "$pid" = "$$" ] && continue
  kill -9 "$pid" 2>/dev/null
done
sleep 1

echo "=== 2. Stop all relay ==="
for pid in $(pgrep -f 'ommega/relay' ; pgrep -f 'libs/arm64-v8a/relay'); do
  kill -9 "$pid" 2>/dev/null
done
sleep 1

echo "=== 3. Clear pid files ==="
rm -f /data/adb/ommega/relay.pid /data/adb/ommega/relay-daemon.pid

echo "=== 4. Replace with new daemon-relay ==="
cp /data/local/tmp/daemon-relay /data/adb/modules/ommegaclient_b/daemon-relay
chmod 0755 /data/adb/modules/ommegaclient_b/daemon-relay

echo "=== 5. Verify new version has no kill logic ==="
grep -c kill_duplicates /data/adb/modules/ommegaclient_b/daemon-relay || true
wc -c /data/adb/modules/ommegaclient_b/daemon-relay

echo "=== 6. Start a single daemon ==="
nohup sh /data/adb/modules/ommegaclient_b/daemon-relay >/dev/null 2>&1 &
echo "daemon started, pid=$!"
sleep 3

echo "=== 7. Verify processes ==="
ps -A | grep -E 'daemon-relay|relay' | grep -v grep
