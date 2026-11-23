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
