#pragma once
#include <windows.h>
#include <string>

// Preserve the first failure and stop issuing writes after it. This is not a
// transaction: earlier keys may already have been saved when a later key fails.
struct KozIniWriter {
 std::wstring path,section,key;
 DWORD error=ERROR_SUCCESS;
 bool ok() const {return error==ERROR_SUCCESS;}
 void put(const std::wstring& file,const wchar_t* group,const wchar_t* name,const wchar_t* value){
  if(!ok())return;
  SetLastError(ERROR_SUCCESS);
  if(WritePrivateProfileStringW(group,name,value,file.c_str()))return;
  error=GetLastError();
  if(error==ERROR_SUCCESS)error=ERROR_WRITE_FAULT;
  path=file;section=group;key=name;
 }
};
