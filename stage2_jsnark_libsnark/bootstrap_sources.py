"""Fetch pinned upstream sources without changing the existing ZKP backend."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
from build_backend import ROOT, DEP, JSNARK_COMMIT, LIBSNARK_COMMIT

def git(*args):
    subprocess.run(['git','-c','http.sslBackend=openssl','-c','http.version=HTTP/1.1',*map(str,args)],check=True)

def main():
    DEP.mkdir(exist_ok=True)
    folder=DEP/'jsnark'
    if not folder.exists():git('clone','--no-checkout','https://github.com/akosba/jsnark.git',folder)
    git('-C',folder,'fetch','origin',JSNARK_COMMIT)
    git('-C',folder,'checkout','--detach',JSNARK_COMMIT)
    git('-C',folder,'submodule','update','--init','libsnark')
    snark=folder/'libsnark'
    head=subprocess.check_output(['git','-C',str(snark),'rev-parse','HEAD'],text=True).strip()
    if head!=LIBSNARK_COMMIT:raise RuntimeError('Wrong jsnark libsnark submodule revision')
    # Only these dependencies are used by the additive ALT_BN128 backend.
    # The unused historical profiling paths contain ':' and cannot be checked
    # out on Windows. Sparse checkout omits them, never library source files.
    git('-C',snark,'submodule','update','--init','depends/libff')
    fq=snark/'depends/libfqfft'
    if os.name=='nt':
        commit=subprocess.check_output(['git','-C',str(snark),'ls-tree','HEAD','depends/libfqfft'],text=True).split()[2]
        if not fq.exists() or not (fq/'.git').exists():
            git('clone','--no-checkout','https://github.com/scipr-lab/libfqfft.git',fq)
        git('-C',fq,'fetch','origin',commit)
        git('-C',fq,'config','core.protectNTFS','false')
        git('-C',fq,'sparse-checkout','set','--no-cone','/*','!/libfqfft/profiling/')
        git('-C',fq,'read-tree','-mu',commit)
        git('-C',fq,'checkout','--detach',commit)
    else:git('-C',snark,'submodule','update','--init','depends/libfqfft')
    print('PINNED_JSNARK_SOURCES_READY')

if __name__=='__main__':main()
