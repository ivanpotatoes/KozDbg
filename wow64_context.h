#pragma once
#include <windows.h>
#include <array>
#include <cstdint>
#include <cstring>

namespace KozWow64 {
inline FARPROC local(const char* name){const auto m=GetModuleHandleW(L"ntdll.dll");return m?GetProcAddress(m,name):nullptr;}
using Read64=LONG(NTAPI*)(HANDLE,uint64_t,void*,uint64_t,uint64_t*);
using Query64=LONG(NTAPI*)(HANDLE,ULONG,void*,ULONG,ULONG*);
using Write64=LONG(NTAPI*)(HANDLE,uint64_t,const void*,uint64_t,uint64_t*);
inline bool readTarget(HANDLE process,uint64_t at,void* out,size_t size){
 static auto fn=reinterpret_cast<Read64>(local("NtWow64ReadVirtualMemory64"));uint64_t done=0;
 return fn&&fn(process,at,out,size,&done)>=0&&done==size;
}
inline bool writeTarget(HANDLE process,uint64_t at,const void* data,size_t size){
 static auto fn=reinterpret_cast<Write64>(local("NtWow64WriteVirtualMemory64"));uint64_t done=0;
 return fn&&fn(process,at,data,size,&done)>=0&&done==size;
}
inline uint64_t targetPeb(HANDLE process){
 static auto fn=reinterpret_cast<Query64>(local("NtWow64QueryInformationProcess64"));std::array<uint64_t,6> basic{};
 return fn&&fn(process,0,basic.data(),sizeof(basic),nullptr)>=0?basic[1]:0;
}
inline bool read(uint64_t at,void* out,size_t size){
 static auto fn=reinterpret_cast<Read64>(local("NtWow64ReadVirtualMemory64"));
 HANDLE self=OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,GetCurrentProcessId());
 uint64_t done=0;const bool ok=self&&fn&&fn(self,at,out,size,&done)>=0&&done==size;
 if(self)CloseHandle(self);return ok;
}
template<class T> bool read(uint64_t at,T& out){return read(at,&out,sizeof(out));}
inline uint64_t nativeNtdll(){
 static uint64_t cached=0;if(cached)return cached;
 BOOL wow=FALSE;SYSTEM_INFO info{};GetNativeSystemInfo(&info);
 if(info.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_AMD64||!IsWow64Process(GetCurrentProcess(),&wow)||!wow)return 0;
 auto query=reinterpret_cast<Query64>(local("NtWow64QueryInformationProcess64"));
 std::array<uint64_t,6> basic{};
 if(!query||query(GetCurrentProcess(),0,basic.data(),sizeof(basic),nullptr)<0)return 0;
 uint64_t ldr=0,node=0;if(!read(basic[1]+0x18,ldr)||!ldr||!read(ldr+0x10,node))return 0;
 for(unsigned i=0;i<64&&node&&node!=ldr+0x10;i++){
  uint16_t length=0;uint64_t name=0,base=0;std::array<wchar_t,64> text{};
  if(!read(node+0x58,length)||!read(node+0x60,name)||!read(node+0x30,base))return 0;
  if(length&&length<sizeof(text)&&read(name,text.data(),length)&&!_wcsicmp(text.data(),L"ntdll.dll")){cached=base;return base;}
  if(!read(node,node))return 0;
 }return 0;
}
inline uint64_t resolve(const char* wanted){
 const auto base=nativeNtdll();IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS64 nt{};IMAGE_EXPORT_DIRECTORY ex{};
 if(!base||!read(base,dos)||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0||!read(base+dos.e_lfanew,nt)||nt.Signature!=IMAGE_NT_SIGNATURE)return 0;
 const auto dir=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
 if(!dir.VirtualAddress||!read(base+dir.VirtualAddress,ex)||ex.NumberOfNames>65536)return 0;
 for(uint32_t i=0;i<ex.NumberOfNames;i++){
  uint32_t rva=0;std::array<char,128> name{};
  if(!read(base+ex.AddressOfNames+4ull*i,rva)||!read(base+rva,name.data(),name.size()))return 0;
  if(!memchr(name.data(),0,name.size())||strcmp(name.data(),wanted))continue;
  uint16_t ordinal=0;uint32_t target=0;
  if(!read(base+ex.AddressOfNameOrdinals+2ull*i,ordinal)||ordinal>=ex.NumberOfFunctions||!read(base+ex.AddressOfFunctions+4ull*ordinal,target))return 0;
  if(target>=dir.VirtualAddress&&target-dir.VirtualAddress<dir.Size)return 0;
  return base+target;
 }return 0;
}
// Four-argument native NTDLL call. Both sides retain the original x86 stack.
// The x64 callee receives aligned RSP and its required 32-byte home space.
__declspec(naked) static LONG __cdecl call4(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t){
 __asm {
  push ebp
  mov ebp,esp
  push ebx
  push esi
  push edi
  push fs
  mov ax,2bh
  mov fs,ax
  push 33h
  _emit 0xe8
  _emit 0
  _emit 0
  _emit 0
  _emit 0
  add dword ptr [esp],5
  retf
  // mov rcx,[rbp+10h]; mov rdx,[rbp+18h]; mov rax,[rbp+8]
  _emit 0x48
  _emit 0x8b
  _emit 0x4d
  _emit 0x10
  _emit 0x48
  _emit 0x8b
  _emit 0x55
  _emit 0x18
  _emit 0x48
  _emit 0x8b
  _emit 0x45
  _emit 0x08
  // mov r8,[rbp+20h]; mov r9,[rbp+28h]
  _emit 0x4c
  _emit 0x8b
  _emit 0x45
  _emit 0x20
  _emit 0x4c
  _emit 0x8b
  _emit 0x4d
  _emit 0x28
  // save RSP in nonvolatile RSI, align and allocate home space
  _emit 0x48
  _emit 0x89
  _emit 0xe6
  _emit 0x48
  _emit 0x83
  _emit 0xe4
  _emit 0xf0
  _emit 0x48
  _emit 0x83
  _emit 0xec
  _emit 0x20
  call eax
  _emit 0x48
  _emit 0x89
  _emit 0xf4
  // 64-bit CALL pushes eight bytes; replace the high half with x86 CS.
  _emit 0xe8
  _emit 0
  _emit 0
  _emit 0
  _emit 0
  mov dword ptr [esp+4],23h
  add dword ptr [esp],13
  retf
  mov dx,ds
  mov ss,dx
  pop fs
  pop edi
  pop esi
  pop ebx
  pop ebp
  ret
 }
}
struct alignas(16) Context {
 std::array<unsigned char,1232> bytes{};
 uint64_t q(size_t offset)const{uint64_t v=0;memcpy(&v,bytes.data()+offset,8);return v;}
 void q(size_t offset,uint64_t v){memcpy(bytes.data()+offset,&v,8);}
 uint32_t d(size_t offset)const{uint32_t v=0;memcpy(&v,bytes.data()+offset,4);return v;}
 void d(size_t offset,uint32_t v){memcpy(bytes.data()+offset,&v,4);}
};
inline bool get(HANDLE thread,Context& c){
 static const auto fn=resolve("NtGetContextThread");c.d(48,0x100013);
 return fn&&call4(fn,reinterpret_cast<uintptr_t>(thread),reinterpret_cast<uintptr_t>(c.bytes.data()),0,0)>=0;
}
inline bool set(HANDLE thread,Context& c){
 static const auto fn=resolve("NtSetContextThread");c.d(48,0x100003);
 return fn&&call4(fn,reinterpret_cast<uintptr_t>(thread),reinterpret_cast<uintptr_t>(c.bytes.data()),0,0)>=0;
}
inline bool setDebug(HANDLE thread,Context& c){
 static const auto fn=resolve("NtSetContextThread");c.d(48,0x100010);
 return fn&&call4(fn,reinterpret_cast<uintptr_t>(thread),reinterpret_cast<uintptr_t>(c.bytes.data()),0,0)>=0;
}
inline bool ssn(const char* name,uint32_t& out){
 const auto fn=resolve(name);std::array<unsigned char,12> b{};
 if(!fn||!read(fn,b.data(),b.size())||memcmp(b.data(),"\x4c\x8b\xd1\xb8",4))return false;
 memcpy(&out,b.data()+4,4);return true;
}
}
