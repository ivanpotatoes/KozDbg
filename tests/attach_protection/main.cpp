#include <windows.h>
#include <array>
#include <cstdint>
#include <cstring>

static_assert(sizeof(void*)==4,"Build the x86 fixture");
#pragma section(".fixture",read,execute)
#pragma comment(linker,"/SECTION:.fixture,ERW")
__declspec(allocate(".fixture")) __declspec(align(4096)) unsigned char sites[4096]{};
extern "C" __declspec(dllexport) volatile LONG phase=0;
extern "C" __declspec(dllexport) __declspec(noinline) void before_patch(){MemoryBarrier();}
static DWORD WINAPI terminate_on_breakin(void*){
 TerminateProcess(GetCurrentProcess(),0xdeadc0de);return 0;
}
int WINAPI WinMain(HINSTANCE,HINSTANCE,LPSTR,int){
 auto entry=reinterpret_cast<unsigned char*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"DbgUiRemoteBreakin"));
 if(!entry)return 1;
 std::array<unsigned char,32> original{};memcpy(original.data(),entry,original.size());
 // Unexecuted scanner markers let the full 380 profile arm in this fixture.
 sites[0]=0xea;const auto marker=reinterpret_cast<uintptr_t>(sites+128);
 memcpy(sites+1,&marker,4);sites[5]=0x33;sites[64]=0x0f;sites[65]=5;sites[66]=0x50;
 before_patch(); // Set a user software breakpoint at the entry here, if desired.
 std::array<unsigned char,5> jump{0xe9};
 const auto displacement=reinterpret_cast<uintptr_t>(terminate_on_breakin)-reinterpret_cast<uintptr_t>(entry)-5;
 memcpy(jump.data()+1,&displacement,4);
 DWORD prior=0;SIZE_T written=0;
 if(!VirtualProtect(entry,32,PAGE_EXECUTE_READWRITE,&prior))return 2;
 const BOOL success=WriteProcessMemory(GetCurrentProcess(),entry,jump.data(),jump.size(),&written);
 DWORD ignored=0;VirtualProtect(entry,32,prior,&ignored);
 FlushInstructionCache(GetCurrentProcess(),entry,32);
 if(!success||written!=jump.size())return 3;
 // A live user INT3 is allowed; all remaining bytes must have been restored.
 bool restored=memcmp(entry+1,original.data()+1,31)==0&&(entry[0]==original[0]||entry[0]==0xcc);
 phase=restored?1:-1;
 MessageBoxW(nullptr,restored?L"PASS: entry restored. Pause the debugger now.":L"FAIL: entry remains patched",L"KozDbg attach regression",MB_OK);
 return restored?0:4;
}
