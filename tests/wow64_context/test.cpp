#include "../../wow64_context.h"
#include <cstdio>
int main(int argc,char** argv){
 if(argc==2&&!strcmp(argv[1],"--peb")){
  HANDLE process=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_VM_OPERATION,FALSE,GetCurrentProcessId());
  const auto peb=process?KozWow64::targetPeb(process):0;unsigned char before=0,after=0;
  bool ok=peb&&KozWow64::readTarget(process,peb+2,&before,1);
  if(ok){
   const unsigned char changed=before^1;
   ok=KozWow64::writeTarget(process,peb+2,&changed,1)&&KozWow64::readTarget(process,peb+2,&after,1)&&after==changed;
   const bool restored=KozWow64::writeTarget(process,peb+2,&before,1)&&KozWow64::readTarget(process,peb+2,&after,1)&&after==before;
   ok=ok&&restored;
  }
  if(process)CloseHandle(process);puts(ok?"PASS: native WOW64 PEB read, write and restoration":"FAIL: native WOW64 PEB access");return ok?0:1;
 }
 setvbuf(stdout,nullptr,_IONBF,0);if(argc!=2)return 2;
 auto fn=reinterpret_cast<KozWow64::Query64>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtWow64QueryInformationProcess64"));
 std::array<uint64_t,6> b{};printf("query=%lx ",fn?fn(GetCurrentProcess(),0,b.data(),sizeof(b),nullptr):-1);for(auto v:b)printf("%llx ",v);puts("");
 uint64_t ldr=0,node=0,done=0;auto rd=reinterpret_cast<KozWow64::Read64>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtWow64ReadVirtualMemory64"));printf("rd=%p status=%lx done=%llu\n",rd,rd?rd(GetCurrentProcess(),b[1]+0x18,&ldr,8,&done):-1,done);printf("read=%d ",KozWow64::read(b[1]+0x18,ldr));printf("ldr=%llx ",ldr);KozWow64::read(ldr+0x10,node);printf("node=%llx\n",node);
 for(unsigned i=0;i<8&&node;i++){uint64_t base=0,name=0;uint16_t len=0;wchar_t str[100]{};KozWow64::read(node+0x30,base);KozWow64::read(node+0x58,len);KozWow64::read(node+0x60,name);if(len<sizeof(str))KozWow64::read(name,str,len);printf("entry=%llx base=%llx len=%u name=%ls\n",node,base,len,str);KozWow64::read(node,node);}
 DWORD tid=strtoul(argv[1],nullptr,10);HANDLE h=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,tid);
 KozWow64::Context c;bool ok=h&&KozWow64::get(h,c);printf("get=%d ntdll=%llx rip=%llx rsp=%llx rax=%llx r8=%llx\n",ok,KozWow64::nativeNtdll(),c.q(248),c.q(152),c.q(120),c.q(184));
 if(h)CloseHandle(h);return ok?0:1;
}
