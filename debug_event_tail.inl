// TitanEngine reaches this import after the core's debug-event callbacks and
// before Windows resumes the debuggee. This is an IAT change in the debugger
// process only; it does not alter target code or any analyst DLL breakpoint.
// The plugin is pinned before installation because another thread may already
// have fetched our call pointer when removal restores the IAT slot.
static bool moduleHardwareTail(DWORD process,DWORD thread);
#include "debug_event_status.h"
using DebugEventTailProc=BOOL(WINAPI*)(DWORD,DWORD,DWORD);
using DebugEventDataProc=DEBUG_EVENT* (__cdecl*)();
static std::atomic<DebugEventDataProc> debugEventData{nullptr};
static std::atomic<unsigned long long> debugEventStatusRepairs{0};
static std::atomic<DebugEventTailProc> debugEventTailOriginal{nullptr};
static std::atomic<unsigned> debugEventTailFrames{0};
static std::atomic<bool> debugEventTailEnabled{false};
static std::atomic_flag debugEventTailMutation=ATOMIC_FLAG_INIT;
static void* volatile* debugEventTailSlot=nullptr;
static bool debugEventTailPinned=false,debugEventTailProtectDirty=false;
static DWORD debugEventTailSavedProtection=0;
static thread_local bool debugEventTailInside=false;

static BOOL WINAPI debugEventTailContinue(DWORD process,DWORD thread,DWORD status) {
 const DWORD callerError=GetLastError();
 debugEventTailFrames.fetch_add(1,std::memory_order_acq_rel);
 const auto original=debugEventTailOriginal.load(std::memory_order_acquire);
 bool proceed=true;
 const bool nested=debugEventTailInside;
 debugEventTailInside=true;
 if(!nested&&debugEventTailEnabled.load(std::memory_order_acquire)){
  try {proceed=moduleHardwareTail(process,thread);}
  catch(...){log("ContinueDebugEvent maintenance raised an exception; refusing an unverified target resume.");proceed=false;}
  if(proceed&&status==0x40010001u){
   const auto getter=debugEventData.load(std::memory_order_acquire);
   const DEBUG_EVENT* source=getter?getter():nullptr;
   DEBUG_EVENT event{};SIZE_T received=0;
   if(source&&ReadProcessMemory(GetCurrentProcess(),source,&event,sizeof(event),&received)&&received==sizeof(event)){
    const DWORD normalized=kozNormalizeContinueStatus(process,thread,event.dwProcessId,event.dwThreadId,event.dwDebugEventCode,status);
    if(normalized!=status){
     status=normalized;
     if(debugEventStatusRepairs.fetch_add(1)==0)log("Corrected stale DBG_REPLY_LATER on a non-exception debug event; exception delivery remains unchanged.");
    }
   }
  }
 }
 debugEventTailInside=nested;
 // The original pointer remains valid after removal for an in-flight call.
 SetLastError(callerError);
 BOOL result=FALSE;
 if(proceed&&original)result=original(process,thread,status);
 else SetLastError(proceed?ERROR_INVALID_FUNCTION:ERROR_OPERATION_ABORTED);
 const DWORD returnError=GetLastError();
 debugEventTailFrames.fetch_sub(1,std::memory_order_acq_rel);
 SetLastError(returnError);
 return result;
}

static bool debugEventTailRead(duint address,void* data,size_t size) {
 SIZE_T received=0;
 return ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(address),data,size,&received)&&received==size;
}
static bool debugEventTailRange(DWORD imageSize,duint rva,size_t size) {
 return rva<imageSize&&size<=static_cast<size_t>(imageSize-rva);
}
static bool debugEventTailString(duint base,DWORD imageSize,duint rva,std::string& value) {
 value.clear();
 for(unsigned i=0;i<256;i++){
  if(!debugEventTailRange(imageSize,rva+i,1))return false;
  char c=0;if(!debugEventTailRead(base+rva+i,&c,1))return false;
  if(!c)return true;
  value.push_back(c);
 }
 return false;
}
static void* volatile* debugEventTailFindSlot(HMODULE module) {
 if(!module)return nullptr;
 const duint base=reinterpret_cast<duint>(module);
 MEMORY_BASIC_INFORMATION region{};
 if(!VirtualQuery(module,&region,sizeof(region))||region.AllocationBase!=module||region.State!=MEM_COMMIT)return nullptr;
 IMAGE_DOS_HEADER dos{};
 if(!debugEventTailRead(base,&dos,sizeof(dos))||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0)return nullptr;
 // The NT header must be in the readable initial header region, before any
 // offsets from it are used to validate the rest of the loaded image.
 const size_t ntOffset=static_cast<size_t>(dos.e_lfanew);
 if(ntOffset>region.RegionSize||sizeof(IMAGE_NT_HEADERS64)>region.RegionSize-ntOffset)return nullptr;
 IMAGE_NT_HEADERS64 nt{};
 if(!debugEventTailRead(base+ntOffset,&nt,sizeof(nt))||nt.Signature!=IMAGE_NT_SIGNATURE||
    nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt.FileHeader.SizeOfOptionalHeader<sizeof(IMAGE_OPTIONAL_HEADER64)||
    nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC||nt.OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_IMPORT)return nullptr;
 const DWORD imageSize=nt.OptionalHeader.SizeOfImage;
 if(!imageSize||base>std::numeric_limits<duint>::max()-imageSize||
    nt.OptionalHeader.SizeOfHeaders>imageSize||ntOffset+sizeof(nt)>nt.OptionalHeader.SizeOfHeaders)return nullptr;
 const auto imports=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
 if(!imports.VirtualAddress||imports.Size<sizeof(IMAGE_IMPORT_DESCRIPTOR)||
    !debugEventTailRange(imageSize,imports.VirtualAddress,imports.Size))return nullptr;
 const size_t descriptorCount=std::min<size_t>(imports.Size/sizeof(IMAGE_IMPORT_DESCRIPTOR),4096);
 for(size_t i=0;i<descriptorCount;i++){
  IMAGE_IMPORT_DESCRIPTOR descriptor{};
  if(!debugEventTailRead(base+imports.VirtualAddress+i*sizeof(descriptor),&descriptor,sizeof(descriptor)))return nullptr;
  if(!descriptor.Name)break;
  std::string library;
  if(!debugEventTailString(base,imageSize,descriptor.Name,library))return nullptr;
  if(_stricmp(library.c_str(),"kernel32.dll")!=0)continue;
  if(!descriptor.OriginalFirstThunk||!descriptor.FirstThunk||
     !debugEventTailRange(imageSize,descriptor.OriginalFirstThunk,sizeof(IMAGE_THUNK_DATA64))||
     !debugEventTailRange(imageSize,descriptor.FirstThunk,sizeof(void*)))return nullptr;
  const size_t count=std::min<size_t>((imageSize-descriptor.OriginalFirstThunk)/sizeof(IMAGE_THUNK_DATA64),65536);
  for(size_t j=0;j<count;j++){
   IMAGE_THUNK_DATA64 thunk{};
   if(!debugEventTailRead(base+descriptor.OriginalFirstThunk+j*sizeof(thunk),&thunk,sizeof(thunk)))return nullptr;
   if(!thunk.u1.AddressOfData)break;
   if(IMAGE_SNAP_BY_ORDINAL64(thunk.u1.Ordinal))continue;
   if(!debugEventTailRange(imageSize,thunk.u1.AddressOfData,sizeof(WORD)+1))return nullptr;
   std::string symbol;
   if(!debugEventTailString(base,imageSize,thunk.u1.AddressOfData+sizeof(WORD),symbol))return nullptr;
   if(symbol!="ContinueDebugEvent")continue;
   const duint slotRva=descriptor.FirstThunk+j*sizeof(void*);
   if(!debugEventTailRange(imageSize,slotRva,sizeof(void*))||(slotRva&(sizeof(void*)-1)))return nullptr;
   MEMORY_BASIC_INFORMATION slotRegion{};
   const auto slot=reinterpret_cast<void* volatile*>(base+slotRva);
   if(!VirtualQuery(reinterpret_cast<const void*>(base+slotRva),&slotRegion,sizeof(slotRegion))||
      slotRegion.AllocationBase!=module||slotRegion.State!=MEM_COMMIT||
      (slotRegion.Protect&(PAGE_NOACCESS|PAGE_GUARD)))return nullptr;
   return slot;
  }
 }
 return nullptr;
}
static bool debugEventTailRestoreProtection() {
 if(!debugEventTailProtectDirty)return true;
 DWORD ignored=0;
 if(!VirtualProtect(const_cast<void**>(debugEventTailSlot),sizeof(void*),debugEventTailSavedProtection,&ignored)){
  log("ContinueDebugEvent IAT page protection restore failed; cleanup remains pending.");return false;
 }
 debugEventTailProtectDirty=false;return true;
}
static bool debugEventTailSwap(void* expected,void* replacement) {
 MEMORY_BASIC_INFORMATION region{};
 if(!VirtualQuery(const_cast<void**>(debugEventTailSlot),&region,sizeof(region)))return false;
 const DWORD executable=PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY;
 const DWORD writable=(region.Protect&executable)?PAGE_EXECUTE_READWRITE:PAGE_READWRITE;
 DWORD previousProtection=0;
 if(!VirtualProtect(const_cast<void**>(debugEventTailSlot),sizeof(void*),writable,&previousProtection))return false;
 if(!debugEventTailProtectDirty)debugEventTailSavedProtection=previousProtection;
 debugEventTailProtectDirty=true;
 void* previous=InterlockedCompareExchangePointer(debugEventTailSlot,replacement,expected);
 const bool protectedAgain=debugEventTailRestoreProtection();
 return previous==expected&&protectedAgain;
}
static bool installContinueDebugEventTail() {
 if(debugEventTailMutation.test_and_set(std::memory_order_acquire)){log("ContinueDebugEvent hook lifecycle is busy.");return false;}
 bool ok=false;
 do {
  const auto engine=GetModuleHandleW(L"TitanEngine.dll");
  const auto getter=engine?reinterpret_cast<DebugEventDataProc>(GetProcAddress(engine,"GetDebugData")):nullptr;
  if(!getter){log("Cannot resolve TitanEngine debug-event data; tail protection was not installed.");break;}
  debugEventData.store(getter,std::memory_order_release);
  const auto slot=debugEventTailFindSlot(GetModuleHandleW(L"TitanEngine.dll"));
  if(!slot){log("Cannot locate a validated TitanEngine KERNEL32!ContinueDebugEvent import; tail protection was not installed.");break;}
  const auto kernel=GetModuleHandleW(L"kernel32.dll");
  const auto expected=kernel?reinterpret_cast<DebugEventTailProc>(GetProcAddress(kernel,"ContinueDebugEvent")):nullptr;
  void* current=nullptr;
  if(!expected||!debugEventTailRead(reinterpret_cast<duint>(slot),&current,sizeof(current)))break;
  const auto own=reinterpret_cast<void*>(&debugEventTailContinue);
  if(current==own){
   if(slot!=debugEventTailSlot||debugEventTailOriginal.load(std::memory_order_acquire)!=expected){log("Unexpected ownership state for ContinueDebugEvent IAT hook.");break;}
   ok=debugEventTailRestoreProtection();debugEventTailEnabled.store(ok,std::memory_order_release);break;
  }
  if(current!=reinterpret_cast<void*>(expected)){log("ContinueDebugEvent IAT already belongs to another hook; it was not overwritten.");break;}
  if(debugEventTailSlot&&debugEventTailSlot!=slot){log("TitanEngine import mapping changed; restart x64dbg before reinstalling tail protection.");break;}
  if(!debugEventTailPinned){
   HMODULE pinned=nullptr;
   if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
       reinterpret_cast<LPCWSTR>(&debugEventTailFrames),&pinned)){log("Could not pin KozDbg safely; ContinueDebugEvent hook was not installed.");break;}
   debugEventTailPinned=true;
   log("KozDbg is pinned for this x64dbg lifetime to keep in-flight callback pointers valid. Restart x64dbg before replacing the plugin binary.");
  }
  debugEventTailSlot=slot;
  debugEventTailOriginal.store(expected,std::memory_order_release);
  ok=debugEventTailSwap(reinterpret_cast<void*>(expected),own);
  debugEventTailEnabled.store(ok,std::memory_order_release);
  if(!ok)log("ContinueDebugEvent hook installation incomplete or ownership changed; any installed wrapper is forwarding only until cleanup.");
 }while(false);
 debugEventTailMutation.clear(std::memory_order_release);
 return ok;
}
static bool removeContinueDebugEventTail() {
 if(debugEventTailMutation.test_and_set(std::memory_order_acquire)){log("ContinueDebugEvent hook lifecycle is busy; removal deferred.");return false;}
 debugEventTailEnabled.store(false,std::memory_order_release);
 bool ok=true;
 if(debugEventTailSlot){
  void* current=nullptr;
  const auto original=debugEventTailOriginal.load(std::memory_order_acquire);
  if(!original||!debugEventTailRead(reinterpret_cast<duint>(debugEventTailSlot),&current,sizeof(current)))ok=false;
  else if(current==reinterpret_cast<void*>(&debugEventTailContinue))ok=debugEventTailSwap(current,reinterpret_cast<void*>(original));
  else if(current==reinterpret_cast<void*>(original))ok=debugEventTailRestoreProtection();
  else{log("ContinueDebugEvent IAT ownership changed externally; refusing to overwrite the new pointer.");ok=false;}
 }
 // Keep the original function and slot identity for calls that fetched the
 // wrapper before the CAS, and for idempotent reinstallation in this process.
 if(!ok)log("ContinueDebugEvent hook cleanup incomplete; restart x64dbg before replacing KozDbg.");
 debugEventTailMutation.clear(std::memory_order_release);
 return ok;
}

// Keep original hardware slots present throughout core unload processing,
// including evaluation of the analyst's DLL breakpoint conditions. Only the
// uniquely validated module-removal callsite may suppress an engine deletion.
// Ordinary delete/disable commands reach other callsites and always forward.
#include <intrin.h>
static bool moduleHardwareSuppressDelete(DWORD registerIndex);
using DebugModuleDeleteProc=bool(*)(DWORD);
static std::atomic<DebugModuleDeleteProc> debugModuleDeleteOriginal{nullptr};
static std::atomic<duint> debugModuleDeleteCaller{0};
static std::atomic<bool> debugModuleDeleteEnabled{false};
static std::atomic<unsigned> debugModuleDeleteFrames{0};
static void* volatile* debugModuleDeleteSlot=nullptr;
static void* debugModuleDeleteCaptured=nullptr;
static bool debugModuleDeleteProtectDirty=false;
static DWORD debugModuleDeleteSavedProtection=0;

static bool debugModuleDeleteHardware(DWORD registerIndex) {
 const DWORD callerError=GetLastError();
 const duint caller=reinterpret_cast<duint>(_ReturnAddress());
 debugModuleDeleteFrames.fetch_add(1,std::memory_order_acq_rel);
 bool suppress=false;
 if(debugModuleDeleteEnabled.load(std::memory_order_acquire)&&caller==debugModuleDeleteCaller.load(std::memory_order_acquire)){
  try {suppress=moduleHardwareSuppressDelete(registerIndex);}
  catch(...){log("Module hardware deletion guard raised an exception; the existing slot was left intact.");suppress=true;}
 }
 const auto original=debugModuleDeleteOriginal.load(std::memory_order_acquire);
 SetLastError(callerError);
 bool result=suppress;
 if(!suppress){
  if(original)result=original(registerIndex);
  else SetLastError(ERROR_INVALID_FUNCTION);
 }
 const DWORD returnError=GetLastError();
 debugModuleDeleteFrames.fetch_sub(1,std::memory_order_acq_rel);
 SetLastError(returnError);
 return result;
}

struct DebugEventCoreImage {
 duint base=0;
 DWORD size=0;
 IMAGE_NT_HEADERS64 nt{};
 std::vector<IMAGE_SECTION_HEADER> sections;
};
static bool debugEventCoreImage(HMODULE module,DebugEventCoreImage& image) {
 if(!module)return false;
 image.base=reinterpret_cast<duint>(module);
 MEMORY_BASIC_INFORMATION region{};IMAGE_DOS_HEADER dos{};
 if(!VirtualQuery(module,&region,sizeof(region))||region.AllocationBase!=module||region.State!=MEM_COMMIT||
    !debugEventTailRead(image.base,&dos,sizeof(dos))||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0)return false;
 const size_t ntOffset=static_cast<size_t>(dos.e_lfanew);
 if(ntOffset>region.RegionSize||sizeof(image.nt)>region.RegionSize-ntOffset||
    !debugEventTailRead(image.base+ntOffset,&image.nt,sizeof(image.nt)))return false;
 const auto& nt=image.nt;
 if(nt.Signature!=IMAGE_NT_SIGNATURE||nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||
    nt.FileHeader.SizeOfOptionalHeader<sizeof(IMAGE_OPTIONAL_HEADER64)||nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC||
    nt.OptionalHeader.NumberOfRvaAndSizes<=IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT||!nt.FileHeader.NumberOfSections||nt.FileHeader.NumberOfSections>96)return false;
 image.size=nt.OptionalHeader.SizeOfImage;
 const size_t sectionOffset=ntOffset+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt.FileHeader.SizeOfOptionalHeader;
 const size_t sectionBytes=nt.FileHeader.NumberOfSections*sizeof(IMAGE_SECTION_HEADER);
 if(!image.size||image.base>std::numeric_limits<duint>::max()-image.size||nt.OptionalHeader.SizeOfHeaders>image.size||
    !debugEventTailRange(image.size,sectionOffset,sectionBytes)||sectionOffset+sectionBytes>nt.OptionalHeader.SizeOfHeaders)return false;
 image.sections.resize(nt.FileHeader.NumberOfSections);
 return debugEventTailRead(image.base+sectionOffset,image.sections.data(),sectionBytes);
}
static bool debugEventCoreExecutable(const DebugEventCoreImage& image,duint address,size_t size) {
 if(address<image.base||!debugEventTailRange(image.size,address-image.base,size))return false;
 const duint rva=address-image.base;
 for(const auto& section:image.sections){
  const DWORD length=std::max(section.Misc.VirtualSize,section.SizeOfRawData);
  if((section.Characteristics&IMAGE_SCN_MEM_EXECUTE)&&rva>=section.VirtualAddress&&
     rva-section.VirtualAddress<length&&size<=length-(rva-section.VirtualAddress))return true;
 }
 return false;
}
struct DebugEventDelayDescriptor {DWORD attributes,name,module,iat,intTable,bound,unload,time;};
static bool debugEventCoreImports(const DebugEventCoreImage& image,std::array<duint,3>& slots) {
 const auto directory=image.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
 if(!directory.VirtualAddress||directory.Size<sizeof(DebugEventDelayDescriptor)||
    !debugEventTailRange(image.size,directory.VirtualAddress,directory.Size))return false;
 const char* names[]={"DeleteBPX","RemoveMemoryBPX","DeleteHardwareBreakPoint"};
 const size_t descriptors=std::min<size_t>(directory.Size/sizeof(DebugEventDelayDescriptor),4096);
 for(size_t i=0;i<descriptors;i++){
  DebugEventDelayDescriptor descriptor{};
  if(!debugEventTailRead(image.base+directory.VirtualAddress+i*sizeof(descriptor),&descriptor,sizeof(descriptor)))return false;
  if(!descriptor.name)break;
  if(descriptor.attributes!=1)return false; // Only RVA-based delay descriptors.
  std::string library;if(!debugEventTailString(image.base,image.size,descriptor.name,library))return false;
  if(_stricmp(library.c_str(),"TitanEngine.dll")!=0)continue;
  if(!descriptor.intTable||!descriptor.iat||!debugEventTailRange(image.size,descriptor.intTable,sizeof(IMAGE_THUNK_DATA64)))return false;
  const size_t count=std::min<size_t>((image.size-descriptor.intTable)/sizeof(IMAGE_THUNK_DATA64),65536);
  for(size_t j=0;j<count;j++){
   IMAGE_THUNK_DATA64 thunk{};
   if(!debugEventTailRead(image.base+descriptor.intTable+j*sizeof(thunk),&thunk,sizeof(thunk)))return false;
   if(!thunk.u1.AddressOfData)break;
   if(IMAGE_SNAP_BY_ORDINAL64(thunk.u1.Ordinal))continue;
   if(!debugEventTailRange(image.size,thunk.u1.AddressOfData,sizeof(WORD)+1))return false;
   std::string symbol;if(!debugEventTailString(image.base,image.size,thunk.u1.AddressOfData+sizeof(WORD),symbol))return false;
   for(unsigned k=0;k<slots.size();k++)if(symbol==names[k]){
    const duint rva=descriptor.iat+j*sizeof(void*);
    if(slots[k]||!debugEventTailRange(image.size,rva,sizeof(void*))||(rva&(sizeof(void*)-1)))return false;
    slots[k]=image.base+rva;
   }
  }
 }
 return std::all_of(slots.begin(),slots.end(),[](duint slot){return slot!=0;});
}
static bool debugEventCoreLea(duint address,const unsigned char* code,size_t size,duint& target) {
 if(size<7||(code[0]!=0x48&&code[0]!=0x4c)||code[1]!=0x8d||(code[2]&0xc7)!=0x05)return false;
 int32_t displacement=0;memcpy(&displacement,code+3,4);
 return relativeAddress(address,7,displacement,target);
}
static bool debugEventCoreImportThunk(const DebugEventCoreImage& image,duint address,duint& slot) {
 std::array<unsigned char,6> code{};
 if(!debugEventCoreExecutable(image,address,code.size())||!debugEventTailRead(address,code.data(),code.size())||code[0]!=0xff||code[1]!=0x25)return false;
 int32_t displacement=0;memcpy(&displacement,code.data()+2,4);
 return relativeAddress(address,6,displacement,slot);
}
static bool debugEventCoreCallsite(const DebugEventCoreImage& image,const std::array<duint,3>& slots,duint& caller,duint& thunkAddress) {
 static const char* literals[]={
  "Could not delete breakpoint %p! (DeleteBPX)\n",
  "Could not delete memory breakpoint %p! (RemoveMemoryBPX)\n",
  "Could not delete hardware breakpoint %p! (DeleteHardwareBreakPoint)\n"};
 std::array<duint,3> strings{};
 for(const auto& section:image.sections){
  const DWORD length=std::max(section.Misc.VirtualSize,section.SizeOfRawData);
  if(!length||!(section.Characteristics&IMAGE_SCN_MEM_READ)||(section.Characteristics&IMAGE_SCN_MEM_EXECUTE)||
     !debugEventTailRange(image.size,section.VirtualAddress,length))continue;
  std::vector<unsigned char> bytes(length);
  if(!debugEventTailRead(image.base+section.VirtualAddress,bytes.data(),bytes.size()))continue;
  for(unsigned i=0;i<strings.size();i++){
   const size_t size=strlen(literals[i])+1;
   auto found=std::search(bytes.begin(),bytes.end(),literals[i],literals[i]+size);
   if(found==bytes.end())continue;
   if(strings[i]||std::search(found+1,bytes.end(),literals[i],literals[i]+size)!=bytes.end())return false;
   strings[i]=image.base+section.VirtualAddress+static_cast<duint>(found-bytes.begin());
  }
 }
 if(std::any_of(strings.begin(),strings.end(),[](duint value){return !value;}))return false;
 const auto directory=image.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
 if(!directory.VirtualAddress||!directory.Size||directory.Size%sizeof(RUNTIME_FUNCTION)||
    directory.Size/sizeof(RUNTIME_FUNCTION)>131072||!debugEventTailRange(image.size,directory.VirtualAddress,directory.Size))return false;
 std::vector<RUNTIME_FUNCTION> functions(directory.Size/sizeof(RUNTIME_FUNCTION));
 if(!debugEventTailRead(image.base+directory.VirtualAddress,functions.data(),directory.Size))return false;
 std::vector<RUNTIME_FUNCTION> candidates;
 for(const auto& section:image.sections){
  const DWORD length=std::max(section.Misc.VirtualSize,section.SizeOfRawData);
  if(!length||!(section.Characteristics&IMAGE_SCN_MEM_EXECUTE)||!debugEventTailRange(image.size,section.VirtualAddress,length))continue;
  std::vector<unsigned char> bytes(length);
  if(!debugEventTailRead(image.base+section.VirtualAddress,bytes.data(),bytes.size()))return false;
  for(size_t i=0;i+7<=bytes.size();i++){
   const duint pc=image.base+section.VirtualAddress+i;duint target=0;
   if(!debugEventCoreLea(pc,bytes.data()+i,bytes.size()-i,target)||target!=strings[2])continue;
   unsigned matches=0;RUNTIME_FUNCTION match{};
   for(const auto& function:functions)if(pc-image.base>=function.BeginAddress&&pc-image.base<function.EndAddress){match=function;++matches;}
   if(matches!=1||match.BeginAddress>=match.EndAddress||match.EndAddress-match.BeginAddress>0x10000||
      !debugEventCoreExecutable(image,image.base+match.BeginAddress,match.EndAddress-match.BeginAddress))return false;
   if(std::none_of(candidates.begin(),candidates.end(),[&](const RUNTIME_FUNCTION& value){return value.BeginAddress==match.BeginAddress;}))candidates.push_back(match);
  }
 }
 unsigned validCandidates=0;
 for(const auto& function:candidates){
  std::vector<unsigned char> code(function.EndAddress-function.BeginAddress);
  if(!debugEventTailRead(image.base+function.BeginAddress,code.data(),code.size()))return false;
  std::array<unsigned,3> references{},calls{};duint hardwareCaller=0,hardwareThunk=0;
  for(size_t i=0;i<code.size();i++){
   const duint pc=image.base+function.BeginAddress+i;duint target=0;
   if(debugEventCoreLea(pc,code.data()+i,code.size()-i,target))for(unsigned k=0;k<strings.size();k++)if(target==strings[k])++references[k];
   if(code[i]!=0xe8||i+5>code.size())continue;
   int32_t displacement=0;memcpy(&displacement,code.data()+i+1,4);duint slot=0;
   if(!relativeAddress(pc,5,displacement,target)||!debugEventCoreImportThunk(image,target,slot))continue;
   for(unsigned k=0;k<slots.size();k++)if(slot==slots[k]){
    ++calls[k];
    if(k==2){
     if(i+7>code.size()||code[i+5]!=0x84||code[i+6]!=0xc0)return false;
     hardwareCaller=pc+5;hardwareThunk=target;
    }
   }
  }
  if(std::all_of(references.begin(),references.end(),[](unsigned value){return value!=0;})&&calls[0]==1&&calls[1]==1&&calls[2]==1){
   ++validCandidates;caller=hardwareCaller;thunkAddress=hardwareThunk;
  }
 }
 return validCandidates==1;
}
static bool debugModuleDeleteUnresolved(const DebugEventCoreImage& image,duint thunk,duint slot,void* current) {
 if(reinterpret_cast<duint>(current)!=thunk+6)return false;
 std::array<unsigned char,12> code{};
 const duint address=reinterpret_cast<duint>(current);
 if(!debugEventCoreExecutable(image,address,code.size())||!debugEventTailRead(address,code.data(),code.size())||
    code[0]!=0x48||code[1]!=0x8d||code[2]!=0x05||code[7]!=0xe9)return false;
 duint target=0;if(!debugEventCoreLea(address,code.data(),code.size(),target)||target!=slot)return false;
 int32_t displacement=0;memcpy(&displacement,code.data()+8,4);
 return relativeAddress(address+7,5,displacement,target)&&debugEventCoreExecutable(image,target,1);
}
static bool debugModuleDeleteRestoreProtection() {
 if(!debugModuleDeleteProtectDirty)return true;
 DWORD ignored=0;
 if(!VirtualProtect(const_cast<void**>(debugModuleDeleteSlot),sizeof(void*),debugModuleDeleteSavedProtection,&ignored)){
  log("Module deletion IAT page protection restore failed; cleanup remains pending.");return false;
 }
 debugModuleDeleteProtectDirty=false;return true;
}
static bool debugModuleDeleteSwap(void* expected,void* replacement) {
 MEMORY_BASIC_INFORMATION region{};
 if(!VirtualQuery(const_cast<void**>(debugModuleDeleteSlot),&region,sizeof(region)))return false;
 const DWORD executable=PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY;
 DWORD previous=0;
 if(!VirtualProtect(const_cast<void**>(debugModuleDeleteSlot),sizeof(void*),(region.Protect&executable)?PAGE_EXECUTE_READWRITE:PAGE_READWRITE,&previous))return false;
 if(!debugModuleDeleteProtectDirty)debugModuleDeleteSavedProtection=previous;
 debugModuleDeleteProtectDirty=true;
 void* observed=InterlockedCompareExchangePointer(debugModuleDeleteSlot,replacement,expected);
 const bool protectedAgain=debugModuleDeleteRestoreProtection();
 return observed==expected&&protectedAgain;
}
static bool installModuleDeleteGuard() {
 if(debugEventTailMutation.test_and_set(std::memory_order_acquire)){log("Debugger IAT hook lifecycle is busy.");return false;}
 bool ok=false;
 do {
  DebugEventCoreImage image;std::array<duint,3> slots{};duint caller=0,thunk=0;
  if(!debugEventTailPinned||!debugEventCoreImage(GetModuleHandleW(L"x64dbg.dll"),image)||
     !debugEventCoreImports(image,slots)||!debugEventCoreCallsite(image,slots,caller,thunk)){
   log("Could not uniquely validate the core module-removal DeleteHardwareBreakPoint callsite; guard not installed.");break;
  }
  const auto titan=GetModuleHandleW(L"TitanEngine.dll");
  const auto original=titan?reinterpret_cast<DebugModuleDeleteProc>(GetProcAddress(titan,"DeleteHardwareBreakPoint")):nullptr;
  void* current=nullptr;const auto slot=reinterpret_cast<void* volatile*>(slots[2]);
  MEMORY_BASIC_INFORMATION slotRegion{};
  if(!original||!VirtualQuery(reinterpret_cast<const void*>(slots[2]),&slotRegion,sizeof(slotRegion))||
     slotRegion.AllocationBase!=reinterpret_cast<void*>(image.base)||slotRegion.State!=MEM_COMMIT||
     (slotRegion.Protect&(PAGE_NOACCESS|PAGE_GUARD))||!debugEventTailRead(slots[2],&current,sizeof(current)))break;
  const auto own=reinterpret_cast<void*>(&debugModuleDeleteHardware);
  if(current==own){
   if(slot!=debugModuleDeleteSlot||debugModuleDeleteOriginal.load(std::memory_order_acquire)!=original||debugModuleDeleteCaller.load(std::memory_order_acquire)!=caller)break;
   ok=debugModuleDeleteRestoreProtection();debugModuleDeleteEnabled.store(ok,std::memory_order_release);break;
  }
  if(current!=reinterpret_cast<void*>(original)&&!debugModuleDeleteUnresolved(image,thunk,slots[2],current)){
   log("Core DeleteHardwareBreakPoint IAT belongs to another hook; it was not overwritten.");break;
  }
  if(debugModuleDeleteSlot&&debugModuleDeleteSlot!=slot){log("Core import mapping changed; restart x64dbg before reinstalling deletion protection.");break;}
  debugModuleDeleteSlot=slot;debugModuleDeleteCaptured=current;
  debugModuleDeleteOriginal.store(original,std::memory_order_release);debugModuleDeleteCaller.store(caller,std::memory_order_release);
  ok=debugModuleDeleteSwap(current,own);debugModuleDeleteEnabled.store(ok,std::memory_order_release);
  if(ok)logf("[KozDbg] Validated core module-removal caller %p; hardware deletion guard installed by import identity.\n",(void*)caller);
  else log("Module deletion guard installation incomplete; any installed wrapper forwards until cleanup.");
 }while(false);
 debugEventTailMutation.clear(std::memory_order_release);return ok;
}
static bool removeModuleDeleteGuard() {
 if(debugEventTailMutation.test_and_set(std::memory_order_acquire)){log("Debugger IAT hook lifecycle is busy; deletion guard removal deferred.");return false;}
 debugModuleDeleteEnabled.store(false,std::memory_order_release);bool ok=true;
 if(debugModuleDeleteSlot){
  void* current=nullptr;
  const auto original=debugModuleDeleteOriginal.load(std::memory_order_acquire);
  if(!debugModuleDeleteCaptured||!debugEventTailRead(reinterpret_cast<duint>(debugModuleDeleteSlot),&current,sizeof(current)))ok=false;
  else if(current==reinterpret_cast<void*>(&debugModuleDeleteHardware))ok=debugModuleDeleteSwap(current,debugModuleDeleteCaptured);
  else if(current==debugModuleDeleteCaptured||current==reinterpret_cast<void*>(original))ok=debugModuleDeleteRestoreProtection();
  else{log("Core DeleteHardwareBreakPoint IAT ownership changed; refusing to overwrite the new pointer.");ok=false;}
 }
 if(!ok)log("Module deletion guard cleanup incomplete; restart x64dbg before replacing KozDbg.");
 debugEventTailMutation.clear(std::memory_order_release);return ok;
}
static bool installDebugEventTail() {
 if(!installContinueDebugEventTail())return false;
 if(installModuleDeleteGuard())return true;
 removeModuleDeleteGuard();removeContinueDebugEventTail();return false;
}
static bool removeDebugEventTail() {
 const bool guardRemoved=removeModuleDeleteGuard();
 const bool tailRemoved=removeContinueDebugEventTail();
 return guardRemoved&&tailRemoved;
}
