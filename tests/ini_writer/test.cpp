#undef NDEBUG
#include <cassert>
#include <cstdio>
#include "../../ini_writer.h"
int main(){
 wchar_t dir[MAX_PATH]{},file[MAX_PATH]{};
 assert(GetTempPathW(MAX_PATH,dir));assert(GetTempFileNameW(dir,L"kzi",0,file));
 KozIniWriter first;first.put(file,L"Custom",L"Keep",L"42");assert(first.ok());
 HANDLE lock=CreateFileW(file,GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);assert(lock!=INVALID_HANDLE_VALUE);
 KozIniWriter failed;failed.put(file,L"Settings",L"Enabled",L"1");assert(!failed.ok());
 assert(failed.path==file&&failed.section==L"Settings"&&failed.key==L"Enabled");
 const auto error=failed.error;CloseHandle(lock);
 failed.put(file,L"Settings",L"Later",L"9");assert(failed.error==error);
 assert(GetPrivateProfileIntW(L"Settings",L"Later",0,file)==0);
 KozIniWriter retry;retry.put(file,L"Settings",L"Enabled",L"1");assert(retry.ok());
 assert(GetPrivateProfileIntW(L"Settings",L"Enabled",0,file)==1);
 assert(GetPrivateProfileIntW(L"Custom",L"Keep",0,file)==42);
 assert(DeleteFileW(file));
 puts("PASS: locked-file failure, first error retained, no later writes, retry, custom key preserved");
}
