import {KEYS, LEVELS, parseConfig, validateConfig, serializeConfig, readCommand, parseSnapshot, saveCommand} from './relay-config.js';

const $ = id => document.getElementById(id);
let seq = 0;
function exec(command) {
  return new Promise(resolve => {
    const callback = `ommega_b_${Date.now()}_${seq++}`;
    window[callback] = (errno, stdout, stderr) => {
      delete window[callback];
      resolve({errno: Number(errno), stdout: stdout || '', stderr: stderr || ''});
    };
    try { window.ksu.exec(command, '{}', callback); }
    catch { delete window[callback]; resolve({errno: 1, stdout: '', stderr: 'Please open this page from a module manager that supports WebUI.'}); }
  });
}
const moduleDir = '/data/adb/modules/ommegaclient_b';
const relayIds = ['relay-server', 'relay-device', 'relay-machine', 'relay-token', 'file-log-enabled', 'file-log-level', 'logcat-enabled', 'logcat-level'];
const logKeys = KEYS.slice(4);
let snapshot = null;
let savedValues = null;

for (const id of ['file-log-level', 'logcat-level']) {
  for (const level of LEVELS) $(id).add(new Option(level, level));
}
function relayMessage(text, error = false) {
  $('relay-message').textContent = text;
  $('relay-message').className = error ? 'message error' : 'message';
}
function relayBusy(busy) {
  $('relay-fields').disabled = busy || !snapshot;
  $('relay-reload').disabled = busy;
}
function fillRelay(values) {
  relayIds.forEach((id, i) => {
    if ($(id).type === 'checkbox') $(id).checked = values[KEYS[i]] === 'true';
    else $(id).value = values[KEYS[i]];
  });
  $('relay-token').type = 'password';
  $('token-toggle').textContent = 'Show';
  $('token-toggle').setAttribute('aria-pressed', 'false');
}
function relayValues() {
  return Object.fromEntries(relayIds.map((id, i) => [KEYS[i], $(id).type === 'checkbox' ? String($(id).checked) : $(id).value]));
}
async function readRelay() {
  relayBusy(true);
  relayMessage('Reading configuration…');
  try {
    const result = await exec(readCommand());
    if (result.errno !== 0) throw new Error(result.stderr || 'Read failed, please check the manager\'s root permissions.');
    snapshot = parseSnapshot(result.stdout);
    savedValues = parseConfig(snapshot.raw);
    fillRelay(savedValues);
    relayMessage(snapshot.digest === 'missing' ? 'No configuration yet; fill in the connection parameters and save.' : 'Loaded the saved configuration.');
  } catch (error) { snapshot = null; relayMessage(error.message, true); }
  finally { relayBusy(false); }
}
$('relay-form').onsubmit = async event => {
  event.preventDefault();
  if (!snapshot || $('relay-fields').disabled) return;
  let values;
  try { values = validateConfig(relayValues()); }
  catch (error) { relayMessage(error.message, true); return; }
  const connectionChanged = KEYS.slice(0, 4).some(key => values[key] !== savedValues[key]);
  const logsChanged = logKeys.some(key => values[key] !== savedValues[key]);
  if (!connectionChanged && !logsChanged && snapshot.digest !== 'missing') { relayMessage('Configuration unchanged, nothing to save.'); return; }
  const raw = serializeConfig(snapshot.raw, values);
  relayBusy(true);
  relayMessage('Saving…');
  try {
    const result = await exec(saveCommand(raw, snapshot.digest, connectionChanged));
    if (result.errno !== 0) {
      if ((result.stdout + result.stderr).includes('CONFIG_CHANGED')) {
        snapshot = null;
        throw new Error('The configuration was modified by another operation; please reload before saving.');
      }
      throw new Error('Save failed; please reload the configuration and check.');
    }
    // Read the exact saved snapshot; credentials never go to browser storage or logs.
    const loaded = await exec(readCommand());
    if (loaded.errno !== 0) { snapshot = null; throw new Error('Configuration written, but re-read failed; please reload to confirm.'); }
    snapshot = parseSnapshot(loaded.stdout);
    if (snapshot.raw !== raw) { snapshot = null; throw new Error('The configuration changed after saving; please reload to confirm.'); }
    savedValues = values;
    fillRelay(values);
    let notice = 'Configuration saved.';
    if (connectionChanged) notice += ' Connection parameters will be loaded automatically by the running relay.';
    if (logsChanged) notice += ' Log options take effect the next time relay starts.';
    if (result.stdout.includes('SAVED_RELOAD_MARKER_FAILED')) notice += ' The reload notification was not written; loading will be triggered by file monitoring.';
    relayMessage(notice);
  } catch (error) { relayMessage(error.message, true); }
  finally { relayBusy(false); }
};
$('relay-reload').onclick = readRelay;
$('token-toggle').onclick = () => {
  const visible = $('relay-token').type === 'password';
  $('relay-token').type = visible ? 'text' : 'password';
  $('token-toggle').textContent = visible ? 'Hide' : 'Show';
  $('token-toggle').setAttribute('aria-pressed', String(visible));
};

const fields = ['system', 'boot', 'vendor'];
const message = $('message');
const save = $('save');
const valid = value => value === '' || /^\d{4}-(0[1-9]|1[0-2])-([0-2]\d|3[01])$/.test(value);
async function refreshSpl() {
  const result = await exec(`sh "${moduleDir}/spl-control.sh" status`);
  $('status').textContent = result.stdout || result.stderr || 'Status unavailable';
  save.disabled = result.errno !== 0;
  if (result.errno === 0) {
    const values = Object.fromEntries(result.stdout.split('\n').map(line => line.split('=', 2)));
    fields.forEach(name => $(name).value = values[`${name.toUpperCase()}_SPL`] || '');
  }
}
save.onclick = async () => {
  const values = fields.map(name => $(name).value.trim());
  if (!values.every(valid)) { message.className = 'message error'; message.textContent = 'Date format must be YYYY-MM-DD, or leave empty to use the baseline.'; return; }
  save.disabled = true;
  message.className = 'message';
  message.textContent = 'Saving and applying SPL…';
  const args = values.map(value => `'${value}'`).join(' ');
  const result = await exec(`sh "${moduleDir}/spl-control.sh" save ${args}`);
  message.className = result.errno === 0 ? 'message' : 'message error';
  message.textContent = result.errno === 0 ? 'SPL configuration applied.' : `Apply failed: ${result.stderr || result.stdout}`;
  await refreshSpl();
};
$('same').onclick = () => { $('boot').value = $('vendor').value = $('system').value.trim(); };
$('auto').onclick = () => fields.forEach(name => $(name).value = '');
readRelay();
refreshSpl();
exec('pidof relay').then(result => {
  const pids = result.stdout.trim();
  $('relay-status').textContent = result.errno === 0 && /^\d+(\s+\d+)*$/.test(pids) ? `relay running · PID ${pids}` : 'relay run status unconfirmed';
});
