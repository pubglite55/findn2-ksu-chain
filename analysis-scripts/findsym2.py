import struct
KO=r"C:/Users/L1872/Desktop/oppo/lkm-build/out/kernelsu.ko"
d=open(KO,'rb').read()
shoff=struct.unpack_from('<Q',d,0x28)[0]; es=struct.unpack_from('<H',d,0x3a)[0]
n=struct.unpack_from('<H',d,0x3c)[0]; si=struct.unpack_from('<H',d,0x3e)[0]
S=[struct.unpack_from('<IIQQQQIIQQ',d,shoff+i*es) for i in range(n)]
def sn(sh):
    b=d[S[si][4]+sh[0]:]; return b[:b.index(b"\0")].decode(errors='replace')
def symname(off,o):
    b=d[off+o:]; return b[:b.index(b"\0")].decode(errors='replace')
st=None
for s in S:
    if sn(s)==".symtab": st=s; break
SE={"avc_has_perm","avc_ss_reset","avtab_alloc","avtab_destroy","avtab_insert_nonunique",
    "avtab_search_node","avtab_search_node_next","ebitmap_get_bit","ebitmap_set_bit"}
und=[]; secs={}
for s in S: secs[sn(s)]=s
print("  段:", [k for k in secs if k in ('.symtab','.strtab','__ksymtab_strings','.rodata','.text')])
if st:
    strtab=S[st[6]]; off=strtab[4]; cnt=st[5]//24
    for i in range(cnt):
        no,info,other,shndx,val,sz=struct.unpack_from('<IBBHQQ',d,st[4]+i*24)
        x=symname(off,no)
        if x and shndx==0 and x!="__this_module": und.append(x)
    und=sorted(set(und))
    print("  .symtab 未定义符号数 =",len(und))
    hit=[s for s in und if s in SE]
    print("  ★ 未定义符号里的 SELinux 内部符号 =",len(hit),hit)
    if not hit: print("     ⇒ 模块已不再【需要】它们 ⇒ finit_module 的 ENOENT 应消失 ✓✓")
    misc=[s for s in und if s.startswith('avc_') or s.startswith('avtab_') or s.startswith('ebitmap_') or s.startswith('selinux_') or s.startswith('security_')]
    print("  其它 SELinux 相关未定义符号 =",len(misc),misc[:12])
# 那些字符串出现在哪些段（判断是否只是残留字符串）
kst=secs.get('__ksymtab_strings'); ro=secs.get('.rodata')
def count_in(sec):
    if not sec: return 0
    blob=d[sec[4]:sec[4]+sec[5]]
    return sum(blob.count(s.encode()) for s in SE)
print("  __ksymtab_strings 里的 SELinux 名字出现 =",count_in(kst))
print("  .rodata 里的 SELinux 名字出现 =",count_in(ro))
