"""Local-only firmware bridge regression; no credentials or live networking."""
from pathlib import Path
import tempfile,os,subprocess,json,stat,base64
with tempfile.TemporaryDirectory(prefix='sockrocket-rpc-') as directory:
    root=Path(directory);(root/'bin').mkdir();(root/'dbus').mkdir();(root/'bodies').mkdir()
    def executable(path,text):path.write_text(text);path.chmod(0o700)
    (root/'base.sh').write_text('ID=$1\n')
    executable(root/'bin/dbus','#!/bin/sh\ncase "$1" in get) cat "$FIXTURE/dbus/$2" 2>/dev/null;; remove) rm -f "$FIXTURE/dbus/$2";; esac\n')
    executable(root/'bin/curl','#!/bin/sh\nexit 0\n')
    executable(root/'bin/backend','''#!/bin/sh
cat > "$FIXTURE/bodies/${QUERY_STRING#action=}"
printf 'Content-Type: application/json\\nCache-Control: no-cache\\n\\n{"ok":true}\\n'
''')
    bridge=root/'bridge.sh';bridge.write_text(Path('merlin/scripts/sockrocket_api.sh').read_text().replace('. /koolshare/scripts/base.sh','. "'+str(root/'base.sh')+'"'))
    env=dict(os.environ,FIXTURE=str(root),PATH=str(root/'bin')+':'+os.environ['PATH'],SOCKROCKET_BIN=str(root/'bin/backend'),SOCKROCKET_RPC_UPLOAD_DIR=str(root/'upload'),SOCKROCKET_RPC_RUNTIME_DIR=str(root/'runtime'))
    def seed(seq,value,encoded=False):
        body=json.dumps(value,ensure_ascii=False)
        if encoded:
            body=base64.b64encode(body.encode()).decode()
            # Real Softcenter escapes quotes/backslashes when saving fields.
            body=body.replace('\\','\\\\').replace('"','\\"')
        (root/'dbus'/(('sockrocket_rpc_b64_' if encoded else 'sockrocket_rpc_body_')+seq)).write_text(body)
    def run(action,seq):return subprocess.run(['sh',str(bridge),'123456',action,seq],env=env,check=True)
    a='a'*32;b='b'*32
    seed(a,{'value':'A'});seed(b,{'value':'B'})
    jobs=[subprocess.Popen(['sh',str(bridge),'123456',action,seq],env=env) for action,seq in [('version',a),('status',b)]]
    assert all(p.wait()==0 for p in jobs)
    assert json.loads((root/'bodies/version').read_text())=={'value':'A'}
    assert json.loads((root/'bodies/status').read_text())=={'value':'B'}
    assert not list((root/'dbus').iterdir())
    result=root/'upload'/('sockrocket_rpc_'+a+'.json')
    assert stat.S_IMODE(result.stat().st_mode)==0o600
    assert json.loads(result.read_text())['ok']
    run('rpc_ack',a);assert not result.exists()
    encoded='e'*32
    value={'name':'示例 " \\ 节点','url':'https://example.invalid/sub?a=1&b=2'}
    seed(encoded,value,True);run('version',encoded)
    assert json.loads(base64.b64decode((root/'bodies/version').read_text()))==value
    assert not list((root/'dbus').iterdir())

    preview={'text':'DOMAIN,example.invalid,PROXY\n'*200,'group':'自定义'}
    config={'config':base64.b64encode(('nodes: []\n# 测试\n'*160).encode()).decode(),'expected_revision':'saved'}
    snapshot=[dict(group='自定义',rule_type='domain',pattern=f'{n}.example.invalid',target='direct') for n in range(60)]
    replacement=dict(group='自定义',expected_rules=snapshot,text='\n'.join(r['pattern'] for r in snapshot)+'\nnew.invalid')
    node={'uri':'hy2://'+('x'*2200)+'@example.invalid:443'}
    for action,payload in [('batch_add_rules',preview),('replace_rule_group',replacement),
                           ('set_rule_group_enabled',dict(group='自定义',expected_rules=snapshot,enabled=False)),
                           ('add_node',node),('save_config',config)]:
        body=base64.b64encode(json.dumps(payload,ensure_ascii=False).encode()).decode()
        for offset in range(0,len(body),2048):
            (root/'dbus'/('sockrocket_rpc_b64_'+a)).write_text(body[offset:offset+2048])
            subprocess.run(['sh',str(bridge),'123456','rpc_rule_part',a,str(offset)],env=env,check=True)
            assert not (root/'bodies'/action).exists()
        def commit():
            subprocess.run(['sh',str(bridge),'123456',action,a,str(len(body))],env=env,check=True)
        commit()
        assert json.loads(base64.b64decode((root/'bodies'/action).read_bytes()))==payload
        (root/'bodies'/action).unlink()
        commit()
        assert not (root/'bodies'/action).exists(), 'a consumed preview cannot be applied twice'
        (root/'runtime'/('rule-body-'+a)).write_text(body[:-4])
        commit()
        assert not (root/'bodies'/action).exists()
        assert not json.loads(result.read_text())['ok']
        assert not (root/'runtime'/('rule-body-'+a)).exists()

    for action in ['add_rule','batch_add_rules','replace_rule_group','set_rule_group_enabled',
                   'delete_rule_group','add_node','save_config']:
        run(action,a)
        assert not (root/'bodies'/action).exists(), 'missing firmware field must never dispatch an empty mutation'
        assert '未收到' in json.loads(result.read_text())['msg']

    # Exercise the final piece of each capped transfer without dispatching
    # thousands of shell processes. The initial pieces are already on disk.
    stage=root/'runtime'/('rule-body-'+a)
    for action,maximum in [('save_config',11184812),('replace_rule_group',5592408),('add_rule',1398104)]:
        with stage.open('wb') as f:
            f.truncate(maximum-4)
        dbus_field=root/'dbus'/('sockrocket_rpc_b64_'+a)
        dbus_field.write_text('YQ==')
        subprocess.run(['sh',str(bridge),'123456','rpc_rule_part',a,str(maximum-4),action],env=env,check=True)
        assert stage.stat().st_size==maximum
        dbus_field.write_text('YQ==')
        assert subprocess.run(['sh',str(bridge),'123456','rpc_rule_part',a,str(maximum),action],env=env).returncode!=0
        subprocess.run(['sh',str(bridge),'123456',action,a,str(maximum)],env=env,check=True)
        assert (root/'bodies'/action).stat().st_size==maximum
        (root/'bodies'/action).unlink()
        with stage.open('wb') as f:
            f.truncate(maximum+4)
        subprocess.run(['sh',str(bridge),'123456',action,a,str(maximum+4)],env=env,check=True)
        assert not (root/'bodies'/action).exists() and not json.loads(result.read_text())['ok']

    for n in range(1,5):
        slot=root/'runtime'/('slot-'+str(n));slot.mkdir();(slot/'pid').write_text(str(os.getpid()))
    c='c'*32;seed(c,{})
    run('version',c)
    assert json.loads((root/'upload'/('sockrocket_rpc_'+c+'.json')).read_text())['error_code']=='busy'
    d='d'*32;seed(d,{})
    run('stop',d)
    assert json.loads((root/'upload'/('sockrocket_rpc_'+d+'.json')).read_text())['ok']
    executable(root/'bin/backend','#!/bin/sh\nexit 7\n')
    run('stop',d)
    failure=json.loads((root/'upload'/('sockrocket_rpc_'+d+'.json')).read_text())
    assert failure['error_code']=='backend_failed' and failure['exit_code']==7
    assert failure['stage']=='invoke_backend'

print('PASS: concurrent request isolation, body removal, private results, ACK deletion, bounded jobs, priority Stop and backend errors')
