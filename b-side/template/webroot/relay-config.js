export const CONFIG_PATH = '/data/adb/ommega/relay.conf';
export const RELOAD_PATH = '/data/adb/ommega/restart.all';
export const KEYS = [
  'OMMEGA_RELAY_SERVER', 'OMMEGA_RELAY_DEVICE_ID', 'OMMEGA_RELAY_MACHINE_ID',
  'OMMEGA_RELAY_TOKEN', 'OMMEGA_RELAY_LOG_ENABLED', 'OMMEGA_RELAY_LOG_LEVEL',
  'OMMEGA_RELAY_LOGCAT_ENABLED', 'OMMEGA_RELAY_LOGCAT_LEVEL',
];
export const LEVELS = ['off', 'error', 'warn', 'info', 'debug', 'trace'];
const defaults = ['', '', '', '', 'true', 'debug', 'true', 'info'];

export function parseConfig(raw) {
  const values = Object.fromEntries(KEYS.map((key, i) => [key, defaults[i]]));
  for (const row of raw.split('\n')) {
    const line = row.trim();
    if (!line || line.startsWith('#')) continue;
    const split = line.indexOf('=');
    if (split < 0) continue;
    const key = line.slice(0, split).trim();
    if (KEYS.includes(key)) values[key] = line.slice(split + 1).trim();
  }
  // Mirror the daemon's legacy boolean and log-level parsing.
  for (const key of [KEYS[4], KEYS[6]]) {
    values[key] = /^(true|1)$/i.test(values[key]) ? 'true' : 'false';
  }
  for (const [key, fallback] of [[KEYS[5], 'debug'], [KEYS[7], 'info']]) {
    const value = values[key].toLowerCase().replace(/^warning$/, 'warn');
    values[key] = LEVELS.includes(value) ? value : fallback;
  }
  return values;
}

export function validateConfig(input) {
  const values = Object.fromEntries(KEYS.map(key => [key, String(input[key] ?? '').trim()]));
  if (Object.values(values).some(value => /[\s\x00-\x1f\x7f]/.test(value))) {
    throw new Error('Config values must not contain spaces, newlines, or control characters.');
  }
  if (!values[KEYS[0]] || !values[KEYS[1]] || !values[KEYS[3]]) {
    throw new Error('Please fill in the server address, device ID and Token.');
  }
  let url;
  try { url = new URL(values[KEYS[0]]); } catch { throw new Error('Please enter a valid HTTP or HTTPS server address.'); }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) {
    throw new Error('The server address must be an HTTP or HTTPS base address, without credentials, query parameters, or fragments.');
  }
  if (!/^[\x21-\x7e]+$/.test(values[KEYS[3]])) throw new Error('Token may contain only non-whitespace ASCII characters.');
  if (![KEYS[4], KEYS[6]].every(key => ['true', 'false'].includes(values[key])) ||
      ![KEYS[5], KEYS[7]].every(key => LEVELS.includes(values[key]))) {
    throw new Error('Please select valid log toggles and levels.');
  }
  values[KEYS[0]] = values[KEYS[0]].replace(/\/+$/, '');
  return values;
}

export function serializeConfig(raw, values) {
  const pending = new Set(KEYS);
  const lines = [];
  for (const row of raw.replace(/\r\n/g, '\n').split('\n')) {
    const line = row.trim();
    const split = line.indexOf('=');
    const key = split < 0 || line.startsWith('#') ? '' : line.slice(0, split).trim();
    if (!KEYS.includes(key)) lines.push(row);
    else if (pending.delete(key)) lines.push(`${key}=${values[key]}`);
  }
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  for (const key of pending) lines.push(`${key}=${values[key]}`);
  return lines.join('\n') + '\n';
}

export function toBase64(text) {
  return btoa(Array.from(new TextEncoder().encode(text), byte => String.fromCharCode(byte)).join(''));
}
export function fromBase64(text) {
  return new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(atob(text.replace(/\s/g, '')), c => c.charCodeAt(0)));
}
const quote = text => `'${text.replace(/'/g, "'\\''")}'`;

export function readCommand(path = CONFIG_PATH) {
  return `set -eu
conf=${quote(path)}
if [ -f "$conf" ]; then
  payload=$(base64 < "$conf")
  digest=$(printf '%s' "$payload" | base64 -d | sha256sum)
  printf '%s\\n%s\\n' "\${digest%% *}" "$payload"
elif [ -e "$conf" ]; then
  echo "CONFIG_NOT_A_FILE" >&2; exit 1
else
  printf 'missing\\n'
fi`;
}

export function parseSnapshot(stdout) {
  const split = stdout.indexOf('\n');
  const digest = (split < 0 ? stdout : stdout.slice(0, split)).trim();
  if (digest === 'missing') return {digest, raw: ''};
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error('Unable to read the config checksum, please reload.');
  return {digest, raw: fromBase64(stdout.slice(split + 1))};
}

// User input travels as UTF-8 Base64; it is never sourced or evaluated.
export function saveCommand(raw, digest, reload, path = CONFIG_PATH, marker = RELOAD_PATH) {
  if (digest !== 'missing' && !/^[a-f0-9]{64}$/.test(digest)) throw new Error('Invalid config checksum.');
  return `set -eu
umask 077
conf=${quote(path)}
expected=${quote(digest)}
check_current() {
  if [ "$expected" = "missing" ]; then
    [ ! -e "$conf" ] || { echo "CONFIG_CHANGED" >&2; return 3; }
  else
    [ -f "$conf" ] || { echo "CONFIG_CHANGED" >&2; return 3; }
    actual=$(sha256sum "$conf")
    [ "\${actual%% *}" = "$expected" ] || { echo "CONFIG_CHANGED" >&2; return 3; }
  fi
}
check_current
mkdir -p "\${conf%/*}"
next=$(mktemp "$conf.webui.XXXXXX")
backup=
trap 'rm -f "$next"; if [ -n "$backup" ]; then rm -f "$backup"; fi' EXIT
printf '%s' '${toBase64(raw)}' | base64 -d > "$next"
chmod 0600 "$next"
if [ -f "$conf" ]; then
  backup=$(mktemp "$conf.backup.XXXXXX")
  cp "$conf" "$backup"
  chmod 0600 "$backup"
fi
check_current
if [ -n "$backup" ]; then mv -f "$backup" "$conf.webui.bak"; fi
mv -f "$next" "$conf"
${reload ? `if ! touch ${quote(marker)}; then echo "SAVED_RELOAD_MARKER_FAILED"; exit 0; fi` : ''}
echo "SAVED"`;
}
