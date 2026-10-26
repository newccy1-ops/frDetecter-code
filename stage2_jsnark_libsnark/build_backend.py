"""Build the additive Java/jsnark/libsnark backend (no FL/proof experiment)."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parent
DEP=ROOT/'dependencies'
JSNARK_COMMIT='0955389d0aae986ceb25affc72edf37a59109250'
LIBSNARK_COMMIT='a37253cb4dfb6f0f9458f7136c87b6baf4a486f1'
GSON_SHA256='57928d6e5a6edeb2abd3770a8f95ba44dce45f3b23b7a9dc2b309c581552a78b'

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):h.update(block)
    return h.hexdigest()

def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')

def posix(path):
    s=str(Path(path).resolve()).replace('\\','/')
    return '/'+s[0].lower()+s[2:] if len(s)>1 and s[1]==':' else s

def native_command(arguments):
    command=[str(x) for x in arguments]
    if os.name=='nt':
        bash=DEP/'msys64/usr/bin/bash.exe'
        if not bash.is_file():raise RuntimeError('Run bootstrap_msys2.ps1 -InstallPackages first')
        command=[posix(x) if Path(x).is_absolute() else str(x) for x in arguments]
        return [str(bash),'-lc',shlex.join(command)]
    return command

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--java-only',action='store_true');args=p.parse_args()
    build=ROOT/'build';build.mkdir(exist_ok=True);DEP.mkdir(exist_ok=True)
    jsnark=DEP/'jsnark';gson=DEP/'gson-2.11.0.jar'
    for folder,expected in [(jsnark,JSNARK_COMMIT),(jsnark/'libsnark',LIBSNARK_COMMIT)]:
        got=subprocess.check_output(['git','-C',str(folder),'rev-parse','HEAD'],text=True).strip()
        if got!=expected:raise RuntimeError(f'Unexpected dependency commit: {folder}: {got}')
    if not gson.is_file():
        urllib.request.urlretrieve('https://repo.maven.apache.org/maven2/com/google/code/gson/gson/2.11.0/gson-2.11.0.jar',gson)
    if sha(gson)!=GSON_SHA256:raise RuntimeError('Gson checksum mismatch')
    sources=[x for folder in ('circuit','util') for x in (jsnark/'JsnarkCircuitBuilder/src'/folder).rglob('*.java') if 'tests' not in x.parts]
    sources+=list((ROOT/'java').rglob('*.java'))
    classes=build/'classes';classes.mkdir(exist_ok=True)
    argfile=build/'java_sources.args'
    argfile.write_text('\n'.join('"'+x.as_posix()+'"' for x in sources),encoding='utf-8')
    start=time.perf_counter()
    subprocess.run(['javac','-encoding','UTF-8','-cp',str(gson),'-d',str(classes),'@'+str(argfile)],check=True)
    print('JAVA_BUILD_OK',flush=True)
    if not args.java_only:
        subprocess.run(native_command(['cmake','-S',ROOT/'native','-B',build/'native','-DCMAKE_BUILD_TYPE=Release']),check=True)
        subprocess.run(native_command(['cmake','--build',build/'native','-j','4']),check=True)
    manifest={'status':'JAVA_ONLY' if args.java_only else 'PASS','jsnark_commit':JSNARK_COMMIT,'libsnark_commit':LIBSNARK_COMMIT,
        'gson_sha256':GSON_SHA256,'elapsed_seconds':time.perf_counter()-start,
        'java_version':subprocess.run(['java','-version'],capture_output=True,text=True).stderr,
        'backend':'libsnark r1cs_gg_ppzksnark / ALT_BN128; compiler Java/jsnark',
        'point_serialization':'NO_PT_COMPRESSION; bounded canonical proof-coordinate parser',
        'assumptions':['Paper does not pin versions, curve, proof scheme or numeric encoding; these are engineering choices.',
        'Local circuit-specific trusted setup, not an independently audited multiparty ceremony.',
        'Portable build omits unrelated demo targets, procps profiling and assembly optimization; cryptographic library sources are unchanged.']}
    for component in ('depends/libff','depends/libfqfft'):
        folder=jsnark/'libsnark'/component
        manifest[component+'_git_head']=subprocess.check_output(['git','-C',str(folder),'rev-parse','HEAD'],text=True).strip()
    save(build/'build_manifest.json',manifest)

if __name__=='__main__':main()
