#include <windows.h>
#include <cstdint>
#include <cstring>
// x32dbg regression procedure (profile 380): break on before_guard and
// after_protect, apply kz_apply at each stop, then run to the PASS dialog.
// Before the fix, the second apply restored PAGE_READWRITE and the first
// window callback failed with an execute AV followed by C000041D.
#pragma section(".probe",read,write)
#pragma comment(linker,"/SECTION:.probe,ERW")
__declspec(allocate(".probe")) __declspec(align(4096)) unsigned char code[8][4096] = {{0x90}};
static unsigned calls;
extern "C" __declspec(dllexport) __declspec(noinline) void before_guard(){MemoryBarrier();}
extern "C" __declspec(dllexport) __declspec(noinline) void after_protect(){MemoryBarrier();}
static LRESULT CALLBACK procedure(HWND hwnd,UINT message,WPARAM w,LPARAM l){
 ++calls;
 return DefWindowProcW(hwnd,message,w,l);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR,int){
 for(auto& page:code){
 page[0]=0xe9;
 const auto delta=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(procedure)-reinterpret_cast<uintptr_t>(page+5));
 memcpy(page+1,&delta,4);
 page[512]=0xea;const auto target=static_cast<uint32_t>(reinterpret_cast<uintptr_t>(page+32));
 memcpy(page+513,&target,4);page[517]=0x33;page[518]=0;
 page[64]=0x0f;page[65]=5;page[66]=0x50;
 }
 FlushInstructionCache(GetCurrentProcess(),code,sizeof(code));
 DWORD protection=0;
 VirtualProtect(code,sizeof(code),PAGE_READWRITE,&protection);
 before_guard();
 VirtualProtect(code,sizeof(code),PAGE_EXECUTE_READWRITE,&protection);
 after_protect();
 WNDCLASSW cls{};cls.hInstance=instance;cls.lpfnWndProc=reinterpret_cast<WNDPROC>(&code[0][0]);cls.lpszClassName=L"KozCallbackProbe";
 if(!RegisterClassW(&cls))return 2;
 const auto hwnd=CreateWindowExW(0,cls.lpszClassName,L"Callback probe",WS_OVERLAPPEDWINDOW,50,50,320,200,nullptr,nullptr,instance,nullptr);
 if(!hwnd){MessageBoxW(nullptr,L"FAIL: CreateWindowExW",L"Callback test",MB_OK);return 1;}
 ShowWindow(hwnd,SW_SHOW);UpdateWindow(hwnd);
 for(unsigned round=0;round<100;round++)for(auto& page:code){
  SetWindowLongPtrW(hwnd,GWLP_WNDPROC,reinterpret_cast<LONG_PTR>(&page[0]));
  SendMessageW(hwnd,WM_NULL,0,0);
  SetWindowPos(hwnd,nullptr,0,0,320,200,SWP_NOMOVE|SWP_NOZORDER);
 }
 MessageBoxW(hwnd,calls?L"PASS: guarded user callback completed":L"FAIL: callback not invoked",L"Callback test",MB_OK);
 DestroyWindow(hwnd);return calls?0:1;
}
