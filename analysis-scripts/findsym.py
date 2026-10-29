import struct, os, glob
KO=r"C:/Users/L1872/Desktop/oppo/lkm-build/out/kernelsu.ko"
d=open(KO,'rb').read()
shoff=struct.unpack_from('<Q',d,0x28)[0]; shentsize=struct.unpack_from('<H',d,0x3a)[0]
shnum=struct.unpack_from('<H',d,0x3c)[0]; shstrndx=struct.unpack_from('<H',d,0x3e)[0]
# name,type,flags,addr,offset,size,link,info,align,entsize
S=[struct.unpack_from('<IIQQQQIIQQ',d,shoff+i*shentsize) for i in range(shnum)]
def shn(sh):  # section name
    b=d[S[shstrndx][4]+sh[0]:]; return b[:b.index(b"\0")].decode(errors='replace')
def sym_name(strtab_off,off):
    b=d[strtab_off+off:]; return b[:b.index(b"\0")].decode(errors='replace')
symtab=None
for s in S:
    if shn(s)==".symtab": symtab=s; break
print("  .symtab 找到:", symtab is not None)
undef=[]
if symtab:
    stroff=d.index(b"\0",0) # placeholder
    strtab=S[symtab[6]]                 # link -> strtab section
    stroff=strtab[4]                    # offset
    n=symtab[5]//24                     # size / sizeof(Elf64_Sym)
    print("  符号数 =",n)
    for i in range(n):
        no,info,other,shndx,val,sz=struct.unpack_from('<IBBHQQ',d,symtab[4]+i*24)
        x=sym_name(stroff,no)
        if x and shndx==0 and x!="__this_module": undef.append(x)
undef=sorted(set(undef))
print("  .ko 未定义符号数 =",len(undef))
cands=[]
for p in [r"C:/Users/L1872/Desktop/oppo/lkm-build/out/Module.symvers",
          r"C:/Users/L1872/Desktop/kernel-src/android_kernel_oppo_sm8475-oppo-sm8475_b_16.0.0_find_n2/Module.symvers"]:
    if os.path.exists(p): cands.append(p)
cands+=glob.glob(r"C:/Users/L1872/Desktop/oppo/lkm-build/**/Module.symvers",recursive=True)
cands+=glob.glob(r"C:/Users/L1872/Desktop/kernel-src/**/Module.symvers",recursive=True)
print("  Module.symvers 候选 =",len(cands))
exp=set()
for p in cands:
    for ln in open(p,errors='replace'):
        f=ln.split()
        if len(f)>=2 and f[0].startswith('0x'): exp.add(f[1])
print("  内核已导出符号数 =",len(exp))
if exp:
    miss=[s for s in undef if s not in exp]
    print("  ★★★ 模块需要但内核未导出 =",len(miss))
    for s in miss[:40]: print("     MISSING:",s)
else:
    print("  无 symvers ⇒ 模块需要的符号：")
    print(" ", [s for s in undef if not s.startswith('__')][:70])
