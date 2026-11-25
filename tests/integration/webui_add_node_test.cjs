// Exercise the Merlin manual node form with the same controls and submit handler as the page.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const page = fs.readFileSync('merlin/webui/sockrocket.asp', 'utf8');
const elements = new Map();
function srElement(id) {
  assert.ok(page.includes('id="sr-' + id + '"'), 'missing page control ' + id);
  if (!elements.has(id)) elements.set(id, {value: '', checked: false, hidden: false, parentNode: {hidden: false}});
  return elements.get(id);
}
function input(id, value) { srElement('an-' + id).value = value; }
const submissions = [], messages = [];
const c = vm.createContext({
  srElement,
  srShowMsg: message => messages.push(message),
  submitNode: (data, done) => submissions.push({data: JSON.parse(JSON.stringify(data)), done}),
});
const form = page.slice(page.indexOf('function clearAddNodeSecrets()'), page.indexOf('function addNodeFromUri()'));
vm.runInContext(form, c);
assert.match(page, /id="sr-an-proto" onchange="updateAddNodeFields\(\)"/);
assert.match(page, /id="sr-an-hy2-obfs" onchange="updateAddNodeFields\(\)"/);
assert.match(page, /id="sr-an-submit" onclick="addNode\(\)"/);
input('proto', 'hysteria2');
input('name', 'Test');
input('server', '192.0.2.1');
input('port', '443');
c.updateAddNodeFields();
assert.equal(srElement('an-tls-fields').hidden, false);
assert.equal(srElement('an-hy2-fields').hidden, false);
assert.equal(srElement('an-hy2-obfs-pass').parentNode.hidden, true);
c.addNode();
assert.match(messages.pop(), /HY2 认证密码/);
input('pass', 'pw:& 汉');
input('hy2-obfs', 'salamander');
c.updateAddNodeFields();
assert.equal(srElement('an-hy2-obfs-pass').parentNode.hidden, false);
c.addNode();
assert.match(messages.pop(), /混淆方式的密码/);
assert.equal(submissions.length, 0);

input('hy2-obfs-pass', 'obfs: &汉');
input('sni', 'peer.invalid');
input('hy2-pin', 'ab'.repeat(32));
input('hy2-alpn', 'h3');
input('hy2-fp', 'chrome');
input('hy2-mport', '443 , 1000 - 1010');
input('hy2-up', '50');
input('hy2-down', '100');
input('uuid', 'hidden-uuid');
srElement('an-insecure').checked = true;
srElement('an-hy2-fastopen').checked = true;
c.addNode();
const first = submissions.shift();
assert.deepEqual(first.data, {
  name: 'Test', protocol: 'hysteria2', server: '192.0.2.1', port: 443, password: 'pw:& 汉',
  sni: 'peer.invalid', skip_cert_verify: true, hysteria2: {
    alpn: 'h3', pinSHA256: 'ab'.repeat(32), fp: 'chrome', upmbps: '50', downmbps: '100',
    mport: '443,1000-1010', obfs: 'salamander', 'obfs-password': 'obfs: &汉', fastopen: '1'
  }
});
input('hy2-obfs-pass', 'new password');
first.done();
assert.equal(srElement('an-pass').value, '');
assert.equal(srElement('an-hy2-obfs-pass').value, 'new password');

input('hy2-obfs', '');
input('pass', 'test');
c.updateAddNodeFields();
c.addNode();
assert.equal(submissions.shift().data.hysteria2['obfs-password'], undefined);
input('proto', 'shadowsocks');
c.updateAddNodeFields();
assert.equal(srElement('an-hy2-fields').hidden, true);
assert.equal(srElement('an-tls-fields').hidden, true);
c.addNode();
const ss = submissions.shift().data;
assert.equal(ss.sni, undefined);
assert.equal(ss.skip_cert_verify, undefined);
assert.equal(ss.hysteria2, undefined);
c.clearAddNodeSecrets();
assert.equal(srElement('an-hy2-obfs-pass').value, '');
console.log('PASS: manual HY2 fields, credentials, TLS, hopping, obfuscation and protocol switching');

async function checkFileImport() {
  const calls = [], results = [], refreshes = [];
  const context = vm.createContext({
    srElement, TextEncoder, TextDecoder,
    srShowMsg: message => messages.push(message),
    toastResp: result => results.push(result),
    srRequestBodyLimit: () => 8 * 1024 * 1024,
    srApi: (...args) => calls.push(args),
    refreshNodeCatalogs: () => refreshes.push('nodes'), refreshStatus: () => refreshes.push('status')
  });
  vm.runInContext(page.slice(page.indexOf('async function importNodeFile'), page.indexOf('function delNode(i)')), context);
  assert.match(page, /id="sr-node-file"[^>]*onchange="importNodeFile\(this\)"/);
  const text = '[Proxy]\n测试 = trojan, example.invalid, 443, password=sample';
  const file = new Blob([text]);
  const input = {value: 'nodes.conf', files: [file]};
  await context.importNodeFile(input);
  assert.equal(input.value, '');
  const [action, data, complete] = calls.shift();
  assert.equal(action, 'import_nodes');
  assert.equal(data.content, text);
  assert.equal(srElement('node-import').disabled, true);
  complete({ok: true, added: 1, msg: '已添加 1 个节点'});
  assert.equal(srElement('node-import').disabled, false);
  assert.deepEqual(refreshes, ['nodes', 'status']);
  assert.equal(results.length, 1);
  await context.importNodeFile({files: [file]});
  calls.shift()[2]({ok: true, added: 0, updated: 1});
  assert.deepEqual(refreshes, ['nodes', 'status', 'nodes', 'status']);
  await context.importNodeFile({files: [new Blob([new Uint8Array([255])])]});
  assert.equal(calls.length, 0);
  assert.match(messages.pop(), /UTF-8/);
  console.log('PASS: local UTF-8 node file upload, completion, and invalid encoding');
}
checkFileImport().catch(error => { console.error(error); process.exitCode = 1; });
