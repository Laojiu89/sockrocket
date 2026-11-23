// Link imports are read-only until preview confirmation and must stay in one group.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('merlin/webui/sockrocket.asp','utf8');
const elements={},requests=[],messages=[];let discard=true;
const element=id=>elements[id]||={value:'',checked:true,hidden:false,disabled:false,style:{},parentElement:{style:{}},innerHTML:'',textContent:'',focus(){},scrollIntoView(){},setAttribute(){},showModal(){this.open=true;},close(){this.open=false;}};
const c=vm.createContext({URL,confirm:()=>discard,SR_PROXY_GROUPS:[{name:'Japan'}],srElement:element,srApi:(...r)=>requests.push(r),srEsc:v=>String(v??''),srShowMsg:m=>messages.push(m),toastResp(){},setProxyGroupTargets(){},renderDevicePolicies(){},SR_STATE:{status:{running:false,proxy_mode:'rule'},ruleRows:[{index:0,source:'',group:'Emby',rule_type:'domain',pattern:'existing.invalid',target:'group:Japan',enabled:false,priority:3},{index:1,source:'',group:'Other',rule_type:'geoip',pattern:'CN',target:'direct',enabled:true,priority:0}]}});
vm.runInContext(source.slice(source.indexOf('var RULE_TYPE_LABEL'),source.indexOf('var ruleExportPending')),c);c.RULE_RULE_REVISION='revision';c.RULE_TARGET_LABEL['group:Japan']='Japan';c.renderRules();
const request=action=>{const i=requests.findIndex(r=>r[0]===action);assert.ok(i>=0,action);return requests.splice(i,1)[0];};
c.startRuleImport();assert.equal(c.RULE_WORKSPACE_MODE,'import');assert.equal(c.RULE_EDIT_GROUP,null);assert.equal(element('rule-target').value,'group:Japan');
assert.equal(element('rule-batch').value,'');assert.match(element('rule-batch').placeholder,/读取链接后/);
assert.equal(element('rule-import-panel').hidden,false);assert.equal(element('rule-list-panel').hidden,true);
for(const url of ['file:///etc/passwd','https://','https://user:secret@example.invalid/list']){element('rule-import-url').value=url;c.fetchRuleList();assert.equal(requests.length,0);}
element('rule-import-url').value='https://example.invalid/rules.list';c.fetchRuleList();let read=request('fetch_rule_list');
assert.equal(read[1].target,'group:Japan');assert.equal(read[1].group,'Emby');assert.equal(c.rulePending,false,'read does not start a mutation');
c.fetchRuleList();assert.equal(requests.length,0,'duplicate fetch is disabled');
read[2]({ok:true,count:2,skipped:{'IP-ASN':5,'PROCESS-NAME':5},text:'DOMAIN,new.invalid,group:Japan\nGEOIP,CN,DIRECT'});
assert.match(element('rule-import-state').textContent,/IP-ASN × 5、PROCESS-NAME × 5/);
assert.equal(requests.length,0,'successful fetch must not apply');assert.equal(c.ruleWorkspaceDirty(),true);
assert.match(element('rule-batch').value,/group:Japan/);c.previewRuleChanges();assert.equal(requests.length,0);
element('rule-dup').value='replace';c.previewRuleChanges();c.applyRulePreview();let add=request('batch_add_rules');
assert.equal(add[1].replace,false,'link imports cannot overwrite other rules');assert.equal(add[1].group_only,true);assert.equal(add[1].group,'Emby');
assert.ok(!requests.some(r=>r[0]==='replace_rule_group'),'import must never replace the whole group');
add[2]({ok:true});request('get_rules')[2]({ok:true,rules:c.SR_STATE.ruleRows,revision:'v2'});assert.equal(c.RULE_WORKSPACE_MODE,'list');
// Slow responses cannot overwrite edits or write into a different group.
c.startRuleImport();element('rule-import-url').value='https://example.invalid/list';c.fetchRuleList();read=request('fetch_rule_list');
element('rule-target').value='direct';read[2]({ok:true,count:1,text:'DOMAIN,wrong.invalid,PROXY'});assert.equal(element('rule-batch').value,'');assert.match(element('rule-import-state').textContent,/未覆盖草稿/);
c.fetchRuleList();read=request('fetch_rule_list');element('rule-batch').value='DOMAIN,draft.invalid,DIRECT';read[2]({ok:true,count:1,text:'DOMAIN,late.invalid,PROXY'});assert.match(element('rule-batch').value,/draft.invalid/);
c.fetchRuleList();read=request('fetch_rule_list');c.changeRuleGroup('Other');c.startRuleImport();element('rule-import-url').value='https://example.invalid/new-list';c.fetchRuleList();let newest=request('fetch_rule_list');
read[2]({ok:true,count:1,text:'DOMAIN,stale.invalid,PROXY'});assert.equal(c.RULE_IMPORT_PENDING,true,'stale response cannot finish the new request');assert.equal(element('rule-batch').value,'');
newest[3]({ok:false,msg:'链接返回 HTTP 404'});assert.equal(c.RULE_IMPORT_PENDING,false);assert.match(element('rule-import-state').textContent,/404/);assert.equal(c.RULE_SELECTED_GROUP,'Other');
element('rule-batch').value='DOMAIN,keep.invalid,DIRECT';discard=false;c.fetchRuleList();assert.equal(requests.length,0,'reread protects the preview');c.changeRuleGroup('Emby');assert.equal(c.RULE_SELECTED_GROUP,'Other');
discard=true;c.fetchRuleList();read=request('fetch_rule_list');read[3]({error_code:'timeout'});assert.match(element('rule-batch').value,/keep.invalid/);assert.equal(element('rule-import-fetch').disabled,false);
c.openRuleGroupCreator('url');
element('rule-new-group-name').value='Other';c.createRuleGroup();
assert.equal(c.RULE_SELECTED_GROUP,'Other');assert.equal(element('rule-batch').value,'DOMAIN,keep.invalid,DIRECT');
element('rule-new-group-name').value='New from URL';c.createRuleGroup();
assert.equal(c.RULE_WORKSPACE_MODE,'import');assert.equal(requests.length,0);
element('rule-import-url').value='https://example.invalid/list';c.fetchRuleList();read=request('fetch_rule_list');
assert.equal(read[1].group,'New from URL');
read[2]({ok:true,count:1,text:'DOMAIN,one.invalid,PROXY'});
c.previewRuleChanges();assert.equal(requests.length,0);c.applyRulePreview();add=request('batch_add_rules');
assert.equal(add[1].group,'New from URL');assert.equal(add[1].replace,false);
assert.equal(requests.length,0);console.log('PASS: group/node-group import routing, explicit confirmation, append-only requests, validation, stale responses, failures and draft protection');

// An unchanged cached preview sends only its reference. A failed lookup keeps the editor usable.
add[2]({ok:true});request('get_rules')[2]({ok:true,rules:c.SR_STATE.ruleRows,revision:'v3'});
function fetchCachedPreview(text) {
  c.startRuleImport();element('rule-import-url').value='https://example.invalid/large.list';
  c.fetchRuleList();
  const read=request('fetch_rule_list');
  assert.equal(read[1].cache_preview,true);
  read[2]({ok:true,text,count:1800,preview_token:'a'.repeat(96)});
}
const largeText='DOMAIN,cache.example.invalid,DIRECT\n'.repeat(1900);
fetchCachedPreview(largeText);
c.applyRulePreview();add=request('batch_add_rules');
assert.equal(add[1].preview_token,'a'.repeat(96));
assert.equal(Object.hasOwn(add[1],'text'),false);
assert.ok(JSON.stringify(add[1]).length<512);
add[2]({ok:false,preview_unavailable:true,msg:'临时预览已过期，草稿已保留。'});
request('get_rules')[2]({ok:true,rules:c.SR_STATE.ruleRows,revision:'v4'});
assert.match(element('rule-import-state').textContent,/已过期/);
assert.equal(element('rule-batch').value,largeText);
c.previewRuleChanges();c.applyRulePreview();add=request('batch_add_rules');
assert.equal(add[1].text,largeText);
assert.equal(Object.hasOwn(add[1],'preview_token'),false);
add[2]({ok:true});request('get_rules')[2]({ok:true,rules:c.SR_STATE.ruleRows,revision:'v5'});
fetchCachedPreview(largeText);
element('rule-batch').value='DOMAIN,edited.invalid,DIRECT';
c.previewRuleChanges();c.applyRulePreview();add=request('batch_add_rules');
assert.equal(add[1].text,'DOMAIN,edited.invalid,DIRECT');
assert.equal(Object.hasOwn(add[1],'preview_token'),false);
console.log('PASS: unchanged preview reuses token, edited and expired previews submit the retained draft');
