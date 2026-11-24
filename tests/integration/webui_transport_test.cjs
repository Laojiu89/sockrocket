const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const {webcrypto} = require('node:crypto');
const source = fs.readFileSync('merlin/webui/sockrocket.asp', 'utf8');
const requests = [];
class XHR {
  open(method, url) { this.method = method; this.url = url; }
  setRequestHeader() {}
  send(body) { this.body = body; requests.push(this); }
  reply(status, body) { this.status = status; this.responseText = body; this.onload(); }
}
const context = vm.createContext({XMLHttpRequest: XHR, Math, Date, JSON, Uint8Array,
  window: {crypto: webcrypto}, TextEncoder, btoa, location: {hostname: 'router'}, srShowMsg() {},
  setTimeout() { throw Error('unexpected retry'); }});
vm.runInContext(source.slice(source.indexOf('var TRANSPORT ='), source.indexOf('function b64utf8')) + source.slice(source.indexOf('function utf8b64'),source.indexOf('function srEsc')), context);
const messages = [], probeResults = [];
context.srShowMsg = message => messages.push(message);
context.probeTransport(() => probeResults.push(context.TRANSPORT));
let earlyReply = 0;
context.srApi('subscriptions', null, () => earlyReply++);
assert.equal(requests.length, 1, 'navigation during startup shares the pending transport probe');
requests.shift().reply(200, '{"version":"test"}');
const earlyList = requests.shift();
assert.match(earlyList.url, /action=subscriptions$/);
earlyList.reply(200, '{"subs":[]}');
assert.equal(earlyReply, 1);
assert.deepEqual(probeResults, ['cgi']);
let failed;
context.srApi('status', null, () => assert.fail(), error => { failed = error; });
const cgi = requests.shift();
assert.equal(cgi.method, 'POST');
assert.equal(cgi.url, '/cgi-bin/sockrocket.cgi?action=status');
cgi.reply(200, '{"error_code":"read_failed","msg":"status unavailable"}');
assert.equal(failed.error_code, 'read_failed');
assert.deepEqual(messages, ['错误：status unavailable']);
context.probeTransport(() => probeResults.push(context.TRANSPORT));
requests.shift().reply(404, '');
assert.deepEqual(probeResults, ['cgi', 'ksc']);
let first = 0, second = 0, stopped = 0;
context.apiKsc('version', null, () => first++);
context.apiKsc('status', null, () => second++);
assert.equal(requests.length, 1);
const job = JSON.parse(requests[0].body);
assert.ok(Number.isInteger(job.id) && job.id > 0 && job.id < 1000000);
assert.match(job.params[1], /^[0-9a-f]{32}$/);
assert.equal(Object.keys(job.fields)[0], 'sockrocket_rpc_b64_' + job.params[1]);
assert.equal(Buffer.from(job.fields[Object.keys(job.fields)[0]], 'base64').toString(), '{}');
context.apiKsc('stop', {}, () => stopped++);
assert.equal(JSON.parse(requests[1].body).params[0], 'stop', 'stop bypasses long queue');
assert.notEqual(JSON.parse(requests[1].body).params[1], job.params[1]);
requests[0].reply(200, JSON.stringify({result: job.id}));
assert.ok(requests[2].url.includes(job.params[1]));
requests[2].reply(200, '{"version":"test"}');
assert.equal(first, 1);
const cleanup = JSON.parse(requests[3].body);
assert.deepEqual(cleanup.params, ['rpc_ack', job.params[1]]);
assert.deepEqual(cleanup.fields, {});
assert.equal(JSON.parse(requests[4].body).params[0], 'status');
requests[4].reply(200, JSON.stringify({result: JSON.parse(requests[4].body).id}));
requests[5].reply(200, '{"running":false}');
assert.equal(second, 1);
let timeout = 0;
context.apiKsc('add_sub', {}, () => assert.fail(), () => timeout++, 35000);
const add = requests.at(-1);
assert.equal(add.timeout, 35000);
add.ontimeout();
assert.equal(timeout, 1);
context.apiKsc('version', null, () => {});
assert.equal(JSON.parse(requests.at(-1).body).params[0], 'version');
let bootCalls = [];
const boot = source.slice(source.lastIndexOf('probeTransport(function () {'), source.lastIndexOf('</script>'));
vm.runInNewContext(boot, {probeTransport: cb => cb(), srLoadNodes: () => bootCalls.push('nodes'),
  refreshStatus: () => bootCalls.push('status'), srPollUpdate: () => bootCalls.push('update-status'), setInterval() {},
  api: action => assert.fail('page boot must not invoke lifecycle: ' + action)});
assert.deepEqual(bootCalls, ['status', 'nodes', 'update-status']);
console.log('PASS: private request nonce/key, priority Stop, result cleanup, timeout and passive boot');

assert.match(source, /id="sr-hero-state">正在确认服务状态</);
assert.match(source, /id="sr-sb-state">等待状态</);
assert.match(source, /<button[^>]*id="sr-toggle-btn"[^>]* disabled>等待状态</);
const statusUi = {}, statusState = {statusKnown:false, status:{}, nodes:[], lat:{}, page:'home'};
const statusContext = vm.createContext({
  SR_STATE:statusState, srElement: id => statusUi[id] ||= {style:{}},
  updateInboundStatus() {}, renderNetworkControls() {}, setProxyModeUi() {},
  servicePending:false, networkPending:false
});
vm.runInContext(source.slice(source.indexOf('function renderChrome()'), source.indexOf('function setChip(')), statusContext);
statusContext.renderChrome();
assert.equal(statusUi['hero-state'].textContent, '正在确认服务状态');
assert.equal(statusUi['st-probe-sub'].textContent, '等待服务状态');
assert.equal(statusUi['toggle-btn'].disabled, true);
for (const running of [false, true]) {
  statusState.statusKnown = true;
  statusState.status = {running, node_count:0, sub_count:0};
  statusContext.renderChrome();
  assert.equal(statusUi['sb-state'].textContent, running ? '运行中' : '已停止');
  assert.equal(statusUi['toggle-btn'].textContent, running ? '停止服务' : '启动服务');
  assert.equal(statusUi['toggle-btn'].disabled, false);
}
statusState.statusKnown = false;
statusContext.renderChrome();
assert.equal(statusUi['sb-state'].textContent, '状态未知');
assert.equal(statusUi['hero-live'].style.display, 'none');
assert.equal(statusUi['toggle-btn'].disabled, true);
console.log('PASS: initial and unconfirmed service status');

const payload={name:'示例 " \\ 节点',url:'https://example.invalid/sub?a=1&b=2'};
context.apiKscRequest('version',payload,()=>{});
const encoded=JSON.parse(requests.at(-1).body).fields;
const stored=Object.values(encoded)[0].replace(/\\/g,'\\\\').replace(/"/g,'\\"');
assert.deepEqual(JSON.parse(Buffer.from(stored,'base64').toString('utf8')),payload);
console.log('PASS: UTF-8 JSON survives Softcenter field escaping');

{
  const dispatches = [];
  const queue = vm.createContext({
    apiKscRequest(action, data, cb) { dispatches.push({action, cb}); }
  });
  vm.runInContext(source.slice(source.indexOf('var kscQueue'), source.indexOf('function newRequestId')), queue);
  for (const action of ['status', 'stats', 'del_sub', 'node_details', 'sysinfo', 'subscriptions', 'update_status']) {
    queue.apiKsc(action, null, () => {});
  }
  ['status', 'stats', 'del_sub', 'subscriptions', 'node_details', 'sysinfo', 'update_status'].forEach((action, index) => {
    assert.equal(dispatches.length, index + 1, 'only one regular RPC runs at a time');
    assert.equal(dispatches[index].action, action);
    dispatches[index].cb({});
  });
}

const preview={text:'DOMAIN,edited.invalid,DIRECT\n'.repeat(185),group:'测试'};
const configBody = {config:Buffer.from('# 节点\n'.repeat(600)).toString('base64'), expected_revision:'r1'};
const snapshot=Array.from({length:60},(_,i)=>({group:'测试',rule_type:'domain',pattern:i+'.example.invalid',target:'direct'}));
const groupEdit={group:'测试',expected_rules:snapshot,text:snapshot.map(r=>r.pattern).concat('new.invalid').join('\n')};
for (const [action,payload] of [
  ['batch_add_rules',preview],['replace_rule_group',groupEdit],
  ['set_rule_group_enabled',{group:'测试',enabled:false,expected_rules:snapshot}],
  ['add_node',{uri:'hy2://'+'x'.repeat(2200)+'@example.invalid:443'}],['save_config',configBody]
]) {
  context.apiKscRequest(action,payload,()=>{});
  let staged='',packet=JSON.parse(requests.at(-1).body);
  const transfer=packet.params[1];
  while(packet.params[0]==='rpc_rule_part'){
    assert.deepEqual(packet.params,['rpc_rule_part',transfer,String(staged.length),action]);
    const part=packet.fields['sockrocket_rpc_b64_'+transfer];
    assert.ok(part.length>0 && part.length<=2048);
    staged+=part;
    requests.at(-1).reply(200,JSON.stringify({result:packet.id}));
    packet=JSON.parse(requests.at(-1).body);
  }
  assert.deepEqual(JSON.parse(Buffer.from(staged,'base64').toString()),payload);
  assert.deepEqual(packet.params,[action,transfer,String(staged.length)]);
  assert.deepEqual(packet.fields,{});
}
console.log('PASS: rule and config requests are staged in order before commit');

const configElements = {};
const configRequests = [];
let beforeUnload, catalogRefreshes = 0;
const config = vm.createContext({
  srElement: id => configElements[id] ||= { value: '' },
  srApi: (...args) => configRequests.push(args), srRequestBodyLimit: context.srRequestBodyLimit,
  b64utf8: value => Buffer.from(value, 'base64').toString(),
  utf8b64: value => Buffer.from(value).toString('base64'),
  window: { addEventListener: (_, callback) => { beforeUnload = callback; } },
  ruleWorkspaceDirty: () => false, dnsPolicyDirty: false, SR_PAGE_LOADED: {network:true}, SR_STATE: {page:'config'},
  refreshNodeCatalogs() { catalogRefreshes++; },
  srShowMsg() {}, toastResp() {}, setTimeout() {}, refreshStatus() {}
});
vm.runInContext(source.slice(source.indexOf('var savedConfigText'), source.indexOf('function srCheckUpdate()')), config);
config.srLoadConfig();
configRequests.shift()[2]({ok: false, msg: '读取失败'});
assert.equal(configElements['config-state'].textContent, '读取失败');
config.srLoadConfig();
configRequests.shift()[2]({config_base64: Buffer.from('first').toString('base64'), revision: 'r1'});
config.srSaveConfig();
assert.equal(configRequests.length, 0, 'unchanged save cannot restart a service');
const editor = configElements['config-text'];
editor.value = 'draft';
config.configEdited();
config.srSaveConfig();
const staleSave = configRequests.shift();
assert.equal(staleSave[1].expected_revision, 'r1');
staleSave[2]({ok: false, msg: '配置已被其他操作更新'});
assert.equal(editor.value, 'draft');
assert.equal(config.savedConfigText, 'first');
assert.equal(catalogRefreshes, 0, 'rejected edits do not invalidate saved data');
config.srSaveConfig();
configRequests.shift()[2]({ok: false, saved: true, revision: 'r2', msg: '服务重启失败'});
assert.equal(config.savedConfigRevision, 'r2');
assert.equal(config.savedConfigText, 'draft');
assert.equal(catalogRefreshes, 1, 'persisted configuration invalidates node, group and subscription catalogs even after apply failure');
assert.equal(config.SR_PAGE_LOADED.network, false);
assert.match(configElements['config-state'].textContent, /重启失败/);
config.dnsPolicyDirty = true;
let prevented = false;
beforeUnload({preventDefault() { prevented = true; }});
assert.equal(prevented, true, 'unloading the page protects unsaved DNS edits');
console.log('PASS: config read errors, no-op save, stale revisions, apply failure and DNS draft protection');

async function testConfigFiles() {
  const routerBytes = Buffer.from('\uFEFF# 节点\r\nnodes: []\r\n');
  const notices = [];
  let blob, downloaded, revoked;
  const anchor = {click() { downloaded = this.download; }, remove() {}};
  Object.assign(config, {
    atob, Blob, TextDecoder,
    URL: {createObjectURL(value) { blob = value; return 'blob:test'; }, revokeObjectURL(url) { revoked = url; }},
    document: {createElement: () => anchor, body: {appendChild() {}}},
    setTimeout: callback => callback(), srShowMsg: message => notices.push(message)
  });
  editor.value = 'local edits';
  config.srDownloadConfig();
  const [action, , reply] = configRequests.shift();
  assert.equal(action, 'config');
  reply({config_base64:routerBytes.toString('base64')});
  assert.equal(downloaded, 'sockrocket-config.yaml');
  assert.deepEqual(Buffer.from(await blob.arrayBuffer()), routerBytes);
  assert.equal(revoked, anchor.href);
  assert.equal(editor.value, 'local edits');

  const input = {files:[blob], value:'selected'};
  config.confirm = () => false;
  await config.srImportConfig(input);
  assert.equal(input.value, '');
  assert.equal(editor.value, 'local edits');
  config.confirm = () => true;
  for (const file of [new Blob([]), new Blob([Uint8Array.of(0xff)]), {size:6*1024*1024}]) {
    await config.srImportConfig({files:[file]});
    assert.equal(editor.value, 'local edits');
  }
  assert.equal(notices.length, 3);
  let finishRead;
  const delayed = {size:4, arrayBuffer: () => new Promise(resolve => { finishRead = resolve; })};
  const reading = config.srImportConfig({files:[delayed]});
  editor.value = 'newer edits';
  finishRead(Buffer.from('file'));
  await reading;
  assert.equal(editor.value, 'newer edits');

  await config.srImportConfig(input);
  assert.equal(editor.value, '# 节点\r\nnodes: []\r\n');
  assert.equal(configRequests.length, 0);
  config.srSaveConfig();
  const [saveAction, body, restoreSmall] = configRequests.shift();
  assert.equal(saveAction, 'save_config');
  assert.equal(body.expected_revision, 'r2');
  assert.equal(Buffer.from(body.config, 'base64').toString(), editor.value);
  restoreSmall({ok:true,saved:true,revision:'small'});
  const large = Buffer.from('rules:\n' + Array.from({length:24000},(_,i) =>
    '  - {group: Large, rule_type: domain, pattern: n' + i + '.example.invalid, target: direct, enabled: true}\n').join(''));
  assert.ok(large.length > 2 * 1024 * 1024);
  config.srDownloadConfig();
  configRequests.shift()[2]({config_base64:large.toString('base64')});
  assert.deepEqual(Buffer.from(await blob.arrayBuffer()), large);
  await config.srImportConfig({files:[blob],value:'selected'});
  assert.equal(editor.value, large.toString());
  config.srSaveConfig();
  const restore=configRequests.shift();
  assert.equal(restore[0], 'save_config');
  assert.deepEqual(Buffer.from(restore[1].config,'base64'), large);
  console.log('PASS: file download, staged import, large rule backup restore, invalid files and concurrent edits');
}
testConfigFiles().catch(error => { console.error(error); process.exitCode = 1; });

const nodeElements = {}, nodeRequests = [], nodeNotices = [];
let refreshedNodes = 0;
const nodeForm = vm.createContext({
  srElement: id => nodeElements[id] ||= {value:'', focus() {}},
  srShowMsg: (message, kind) => nodeNotices.push([message, kind]),
  srApi: (...args) => nodeRequests.push(args),
  refreshNodeCatalogs: () => refreshedNodes++, refreshStatus() {}
});
vm.runInContext(source.slice(source.indexOf('function addNodeFromUri()'), source.indexOf('function delNode(')), nodeForm);
nodeForm.addNodeFromUri();
assert.equal(nodeRequests.length, 0);
const uriInput = nodeElements['an-uri'];
uriInput.value = 'hy2://key@node.example.invalid#first';
nodeForm.addNodeFromUri();
nodeForm.addNodeFromUri();
assert.equal(nodeRequests.length, 1);
const firstAdd = nodeRequests.shift();
assert.equal(firstAdd[0], 'add_node');
assert.deepEqual({...firstAdd[1]}, {uri:uriInput.value});
assert.equal(nodeElements['an-submit'].disabled, true);
uriInput.value = 'vless://another-edited-draft';
firstAdd[2]({ok:true});
assert.equal(refreshedNodes, 1);
assert.equal(uriInput.value, 'vless://another-edited-draft');
nodeForm.addNodeFromUri();
nodeRequests.shift()[3]({error_code:'timeout'});
assert.equal(uriInput.value, 'vless://another-edited-draft');
assert.equal(nodeNotices.at(-1)[1], 'err');
assert.equal(nodeElements['an-uri-submit'].disabled, false);
nodeForm.addNodeFromUri();
nodeRequests.shift()[2]({ok:true});
assert.equal(uriInput.value, '');
console.log('PASS: single-node share links keep edited drafts, suppress double submits and clear credentials on success');
