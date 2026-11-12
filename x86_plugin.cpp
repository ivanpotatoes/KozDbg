#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#pragma warning(push)
#pragma warning(disable:4324)
#include <_plugins.h>
#include <_scriptapi_register.h>
#include <_scriptapi_flag.h>
#include <_scriptapi_module.h>
#pragma warning(pop)
#include <array>
#include <atomic>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstdarg>
#include "ini_writer.h"
#include "x86_abi.h"
#include "wow64_context.h"
#include "retry_cleanup.h"

static_assert(sizeof(duint)==4,"This backend is for x32dbg only");
namespace R=Script::Register;
static HINSTANCE instance;
static HWND owner,settingsWindow,tooltip;
static int pluginHandle;
static std::wstring iniPath;
static std::atomic<bool> enabled{true},automatic{true},armed{false};
static constexpr unsigned supportedMask=0xfff; // API checks, TF/context handling, attach and TitanHide protection
static std::atomic<unsigned> options{supportedMask};
static std::atomic<unsigned> profile{331};
struct Profile {unsigned id;int menu;const char* label;const wchar_t* wide;const wchar_t* section;};
static constexpr Profile profiles[]={
 {331,1,"VMProtect 3.3.1 - x32",L"VMProtect 3.3.1 - x32",L"Profile.331"},
 {340,7,"VMProtect 3.4.0 - x32",L"VMProtect 3.4.0 - x32",L"Profile.340"},
 {350,8,"VMProtect 3.5.0 - x32",L"VMProtect 3.5.0 - x32",L"Profile.350"},
 {360,9,"VMProtect 3.6.0 - x32",L"VMProtect 3.6.0 - x32",L"Profile.360"},
 {380,10,"VMProtect 3.8.0 - x32",L"VMProtect 3.8.0 - x32",L"Profile.380"},
 {394,11,"VMProtect 3.9.4 - x32",L"VMProtect 3.9.4 - x32",L"Profile.394"},
 {3101,12,"VMProtect 3.10.1 - x32",L"VMProtect 3.10.1 - x32",L"Profile.3101"}};
static bool extendedChecks(){return profile==394||profile==3101;}
static bool gateProfile(){return profile==380||extendedChecks();}
static bool advancedProfile(){return profile==360||gateProfile();}
static unsigned profileMask(unsigned id){return (id==394||id==3101)?supportedMask:0x7ff;}
static const Profile* findProfile(unsigned id){for(const auto& p:profiles)if(p.id==id)return &p;return nullptr;}
static unsigned profileOptions(unsigned id){
 const auto* p=findProfile(id);if(!p)return supportedMask;
 unsigned value=GetPrivateProfileIntW(p->section,L"Controls",((id==360||id==380||id==394||id==3101)?profileMask(id):GetPrivateProfileIntW(L"Settings",L"Controls",0x6ff,iniPath.c_str())),iniPath.c_str())&profileMask(id);
 // Give older profiles a default for the new option without rewriting their INI.
 value&=~(1u<<10);if(GetPrivateProfileIntW(p->section,L"AttachProtection",1,iniPath.c_str()))value|=1u<<10;
 return value;
}

static std::array<std::atomic<unsigned>,12> hits{};
struct Binding {duint address;unsigned action;std::string name,command;};
static std::vector<Binding> owned;
struct Pending {duint address,stack,buffer;DWORD thread;unsigned action;duint size;};
static std::vector<Pending> pending;
static duint pebFlag;
static unsigned char savedPeb;
static uint64_t nativePebFlag=0;
static unsigned char savedNativePeb=0;
static DWORD targetPid;
static DWORD breakinPid;
static duint breakinAddress;
static std::array<unsigned char,32> breakinBytes{};
struct SavedContext {DWORD thread;duint address;DWORD exceptionIp;std::array<DWORD,4> dr;};
static std::vector<SavedContext> contexts;
static unsigned tfWindowEvents=0;
static bool tfDeliveryPending=false;
static bool trustedTf(duint address){
 std::array<unsigned char,4> bytes{};
 return address>=3&&Script::Module::BaseFromAddr(address)==Script::Module::GetMainModuleBase()&&
  DbgMemRead(address-3,bytes.data(),bytes.size())&&bytes==std::array<unsigned char,4>{0x9d,0x0f,0x31,0x90};
}
static bool menuReady;
static bool on(unsigned bit){return (options.load()&(1u<<bit))!=0;}
static void log(const char* format,...){
 char text[2048];va_list ap;va_start(ap,format);vsnprintf_s(text,sizeof(text),_TRUNCATE,format,ap);va_end(ap);
 _plugin_logprintf("[KozDbg x32] %s\n",text);
 const auto path=iniPath+L".log";
 HANDLE file=CreateFileW(path.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(file!=INVALID_HANDLE_VALUE){DWORD done=0;WriteFile(file,text,static_cast<DWORD>(strlen(text)),&done,nullptr);WriteFile(file,"\r\n",2,&done,nullptr);CloseHandle(file);}
}
static std::string hex(duint value){char text[16];sprintf_s(text,"%X",value);return text;}
static bool cmd(const std::string& text){const bool ok=DbgCmdExecDirect(text.c_str());if(!ok)log("Debugger command failed: %s",text.c_str());return ok;}
template<class T> static bool read(duint address,T& value){return DbgMemRead(address,&value,sizeof(value));}
template<class T> static bool write(duint address,const T& value){return DbgMemWrite(address,&value,sizeof(value));}
static bool writable(duint address,size_t size){
 if(!address||size>UINT32_MAX-address)return false;
 MEMORY_BASIC_INFORMATION info{};
 if(!VirtualQueryEx(DbgGetProcessHandle(),reinterpret_cast<void*>(address),&info,sizeof(info))||info.State!=MEM_COMMIT)return false;
 const DWORD access=info.Protect&0xff;
 return !(info.Protect&PAGE_GUARD)&&(access==PAGE_READWRITE||access==PAGE_WRITECOPY||access==PAGE_EXECUTE_READWRITE||access==PAGE_EXECUTE_WRITECOPY)&&
  address>=reinterpret_cast<duint>(info.BaseAddress)&&size<=info.RegionSize-(address-reinterpret_cast<duint>(info.BaseAddress));
}
static bool self(duint value,bool thread=false){
 if(value==(thread?duint(-2):duint(-1)))return true;
 HANDLE copy=nullptr;
 if(!DuplicateHandle(DbgGetProcessHandle(),reinterpret_cast<HANDLE>(value),GetCurrentProcess(),&copy,0,FALSE,DUPLICATE_SAME_ACCESS))return false;
 const DWORD pid=thread?GetProcessIdOfThread(copy):GetProcessId(copy);CloseHandle(copy);
 return pid&&pid==GetProcessId(DbgGetProcessHandle());
}
static bool matches(const Binding& entry,const BRIDGEBP& bp){return bp.addr==entry.address&&entry.name==bp.name;}
static bool removeBinding(const Binding& entry){
 BRIDGEBP bp{};
 if(!DbgFunctions()->GetBridgeBp(bp_normal,entry.address,&bp))return true;
 if(!matches(entry,bp)){log("Breakpoint ownership changed at %08X; leaving it untouched",entry.address);return true;}
 if(!cmd("bc "+hex(entry.address)))return false;
 return !DbgFunctions()->GetBridgeBp(bp_normal,entry.address,&bp)||!matches(entry,bp);
}
static bool addBinding(duint address,unsigned action){
 auto old=std::find_if(owned.begin(),owned.end(),[&](const Binding& b){return b.address==address;});
 if(old!=owned.end())return old->action==action;
 if(!address)return false;
 const std::string a=hex(address),name="KZ32_"+a,command="kz32_hit "+std::to_string(action);
 BRIDGEBP previous{};
 if(DbgGetBpxTypeAt(address)!=bp_none){
  if(!DbgFunctions()->GetBridgeBp(bp_normal,address,&previous)||strncmp(previous.name,"KZ32_",5)||command!=previous.commandText||
   strcmp(previous.breakCondition,"0")||strcmp(previous.commandCondition,"1")||previous.fastResume||!previous.silent){
   log("Existing user breakpoint at %08X; not modified",address);return false;
  }
  if(!cmd("SetBreakpointName "+a+",\""+name+"\"")||!cmd("be "+a))return false;
 }else if(!cmd("bp "+a+",\""+name+"\""))return false;
 owned.push_back({address,action,name,command});
 BRIDGEBP bp{};
 const bool ok=cmd("SetBreakpointCondition "+a+",0")&&cmd("SetBreakpointCommand "+a+",\""+command+"\"")&&
  cmd("SetBreakpointCommandCondition "+a+",1")&&cmd("SetBreakpointFastResume "+a+",0")&&cmd("SetBreakpointSilent "+a+",1")&&
  DbgFunctions()->GetBridgeBp(bp_normal,address,&bp)&&matches(owned.back(),bp)&&bp.enabled&&bp.silent&&!bp.fastResume&&
  command==bp.commandText&&strcmp(bp.breakCondition,"0")==0&&strcmp(bp.commandCondition,"1")==0;
 if(!ok){log("Breakpoint setup failed at %08X; cleanup record retained",address);return false;}
 return true;
}
static duint resolve(const char* symbol,bool native){
 duint address=DbgValFromString(symbol);
 std::vector<duint> seen;
 for(unsigned hop=0;address&&hop<16;hop++){
  if(std::find(seen.begin(),seen.end(),address)!=seen.end())return 0;seen.push_back(address);
  std::array<unsigned char,8> bytes{};if(!DbgMemRead(address,bytes.data(),bytes.size()))return 0;
  if(bytes==std::array<unsigned char,8>{0x8b,0xff,0x55,0x8b,0xec,0x5d,0xff,0x25}){
   duint slot=0;if(!read(address+8,slot)||!read(slot,address))return 0;continue;
  }
  if(bytes[0]==0xe9){int32_t delta=0;memcpy(&delta,bytes.data()+1,4);address=address+5+static_cast<duint>(delta);continue;}
  if(bytes[0]==0xeb){address=address+2+static_cast<duint>(static_cast<int8_t>(bytes[1]));continue;}
  if(bytes[0]==0xff&&bytes[1]==0x25){duint slot=0;memcpy(&slot,bytes.data()+2,4);if(!read(slot,address))return 0;continue;}
  if(native){
   // x86/WOW64 Nt stubs start with MOV EAX,SSN. It does not change ESP.
   BASIC_INSTRUCTION_INFO instruction{};DbgDisasmFastAt(address,&instruction);
   if(bytes[0]!=0xb8||instruction.size!=5){log("Unrecognized x32 Nt stub: %s",symbol);return 0;}
   address+=5;
  }
  return address;
 }
 return 0;
}
static void updateMenu(){if(menuReady){for(const auto& p:profiles)_plugin_menuentrysetchecked(pluginHandle,p.menu,enabled&&profile==p.id);_plugin_menuentrysetchecked(pluginHandle,2,!enabled);_plugin_menuentrysetchecked(pluginHandle,5,automatic);}}
static void saveError(){MessageBoxW(owner,L"Could not save the x32 settings. See the x32dbg log for the file and Windows error.",L"KozDbg",MB_OK|MB_ICONERROR);}
static bool save(){
 KozIniWriter out;out.put(iniPath,L"Settings",L"Enabled",enabled?L"1":L"0");out.put(iniPath,L"Settings",L"AutoArm",automatic?L"1":L"0");
 out.put(iniPath,L"Settings",L"Profile",std::to_wstring(profile.load()).c_str());
 out.put(iniPath,findProfile(profile)->section,L"Controls",std::to_wstring(options.load()).c_str());
 out.put(iniPath,findProfile(profile)->section,L"AttachProtection",on(10)?L"1":L"0");
 if(!out.ok()){log("Settings save failed: %ls [%ls] %ls, Windows error %lu",out.path.c_str(),out.section.c_str(),out.key.c_str(),out.error);GuiExecuteOnGuiThread(saveError);return false;}return true;
}
#include "x86_syscalls.inl"
#include "x86_gate_calls.inl"
static bool disarm(){
 armed=false;bool ok=true;
 if(tfDeliveryPending){_plugin_debugskipexceptions(false);tfDeliveryPending=false;}
 if(DbgIsDebugging()&&WaitForSingleObject(DbgGetProcessHandle(),0)!=WAIT_OBJECT_0){
  ok=gateCleanup()&&ok;
  ok=kozRetryCleanup(contexts,[](const SavedContext& saved){
   CONTEXT current{};const auto at=saved.address+offsetof(CONTEXT,Dr0);
   if(!read(saved.address,current))return false;
   if(current.Eip!=saved.exceptionIp)return true;
   return (current.Dr0|current.Dr1|current.Dr2|current.Dr3)!=0||DbgMemWrite(at,saved.dr.data(),sizeof(saved.dr));
  })&&ok;
  if(pebFlag&&targetPid==GetProcessId(DbgGetProcessHandle())){
   unsigned char value=0;const bool restored=read(pebFlag,value)&&(value!=0||(write(pebFlag,savedPeb)&&read(pebFlag,value)&&value==savedPeb));
   if(restored)pebFlag=0;ok=restored&&ok;
  }
  if(nativePebFlag&&targetPid==GetProcessId(DbgGetProcessHandle())){
   unsigned char value=0;const auto process=DbgGetProcessHandle();
   const bool restored=KozWow64::readTarget(process,nativePebFlag,&value,1)&&(value!=0||
    (KozWow64::writeTarget(process,nativePebFlag,&savedNativePeb,1)&&KozWow64::readTarget(process,nativePebFlag,&value,1)&&value==savedNativePeb));
   if(restored)nativePebFlag=0;ok=restored&&ok;
  }
  ok=clearNativeSites()&&ok;
  ok=clearNativeGates()&&ok;
  ok=kozRetryCleanup(owned,removeBinding)&&ok;
 }
 if(!ok){log("Cleanup incomplete; retry or stop the target");return false;}
 owned.clear();pending.clear();contexts.clear();nativeSites.clear();pebFlag=0;nativePebFlag=0;targetPid=0;return true;
}
static bool apply(int,char**){
 if(DbgIsDebugging()&&DbgIsRunning()){log("Pause before applying");return false;}
 if(!disarm())return false;
 if(!enabled||!DbgIsDebugging())return true;
 IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS32 nt{};const duint base=Script::Module::GetMainModuleBase();
 if(!read(base,dos)||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0||static_cast<duint>(dos.e_lfanew)>UINT32_MAX-base||
  !read(base+static_cast<duint>(dos.e_lfanew),nt)||nt.Signature!=IMAGE_NT_SIGNATURE||nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_I386||nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC){log("Only x32 PE targets are supported");return false;}
 const char* names[]={"kernel32:IsDebuggerPresent","kernel32:CheckRemoteDebuggerPresent","ntdll:NtQueryInformationProcess","ntdll:NtSetInformationThread","ntdll:NtQuerySystemInformation","ntdll:NtClose"};
 std::vector<std::pair<duint,unsigned>> bindings;
 for(unsigned i=0;i<6;i++){
  const bool needed=i==2?(on(1)||on(2)):(i==4?(on(4)||on(5)):on(i==5?6:i));
  if(needed){const auto address=resolve(names[i],i>=2);if(!address){log("Cannot resolve %s",names[i]);return false;}bindings.push_back({address,i});}
 }
 if(on(0)){
  for(auto& b:bindings)if(b.second==0){
   duint pc=b.first;bool found=false;
   for(unsigned n=0;n<32;n++){
    BASIC_INSTRUCTION_INFO instruction{};DbgDisasmFastAt(pc,&instruction);unsigned char opcode=0;
    if(instruction.size<=0||instruction.size>15||!read(pc,opcode)||instruction.branch||instruction.call)break;
    if(opcode==0xc3){b.first=pc;found=true;break;}
    pc+=static_cast<duint>(instruction.size);
   }
   if(!found){log("Cannot decode IsDebuggerPresent return");return false;}
  }
 }
 if(on(1)){const auto address=resolve("kernelbase:CheckRemoteDebuggerPresent",false);if(address)bindings.push_back({address,1});}
 if(on(9)||on(7)){
  const auto dispatcher=resolve("ntdll:KiUserExceptionDispatcher",false),continuation=resolve("ntdll:NtContinue",true);
  if(!dispatcher||!continuation){log("Cannot resolve x32 context dispatch/continuation");return false;}
  bindings.push_back({dispatcher,7});if(on(9))bindings.push_back({continuation,8});
 }
 if(advancedProfile()&&on(8)){const auto address=resolve("ntdll:NtSetInformationProcess",true);if(!address)return false;bindings.push_back({address,9});}
 if(extendedChecks()){
  if(on(11)){const auto address=resolve("ntdll:NtOpenFile",true);if(!address)return false;bindings.push_back({address,18});}
  if(on(3)){const auto address=resolve("ntdll:NtQueryInformationThread",true);if(!address)return false;bindings.push_back({address,19});}
 }
 if(on(10)){
  const auto process=GetProcessId(DbgGetProcessHandle());
  if(breakinPid!=process||!breakinAddress){
   const auto address=DbgValFromString("ntdll:DbgUiRemoteBreakin");
   const auto resolved=resolve("ntdll:DbgUiRemoteBreakin",false);
   if(!address||!resolved||address>UINT32_MAX-breakinBytes.size()||
    Script::Module::BaseFromAddr(resolved)!=Script::Module::BaseFromAddr(address)||
    !DbgMemRead(address,breakinBytes.data(),breakinBytes.size())){
    log("Cannot snapshot a clean DbgUiRemoteBreakin entry; start a fresh target session");return false;
   }
   breakinAddress=address;breakinPid=process;
  }
  const auto address=resolve("kernel32:WriteProcessMemory",false);
  if(!address){log("Cannot resolve WriteProcessMemory for attach protection");return false;}
  bindings.push_back({address,15});
  const auto alias=resolve("kernelbase:WriteProcessMemory",false);if(alias)bindings.push_back({alias,15});
  // Keep debugger-created break-in threads working with a hidden PEB flag.
  // Match the local ntdll check, not an OS-specific address or offset.
  if(on(0)){
   static constexpr unsigned char check[]={0x64,0xa1,0x30,0,0,0,0x80,0x78,0x02,0,0x75};
   const auto found=std::search(breakinBytes.begin(),breakinBytes.end(),std::begin(check),std::end(check));
   if(found==breakinBytes.end()){log("Unrecognized DbgUiRemoteBreakin PEB check; pause compatibility was not installed");return false;}
   bindings.push_back({breakinAddress+static_cast<duint>(found-breakinBytes.begin())+10,16});
  }
 }
 for(const auto& b:bindings)if(!addBinding(b.first,b.second)){disarm();return false;}
 if(gateProfile()&&!gateInitialize()){disarm();return false;}
 if(advancedProfile()&&!installNativeSites(base,nt)){disarm();return false;}
 targetPid=GetProcessId(DbgGetProcessHandle());
 if(on(0)){
  // The x86 TEB contains the 32-bit PEB pointer at FS:[0x30], also on WOW64.
  duint peb=0;const duint teb=DbgGetTebAddress(DbgGetThreadId());
  if(!teb||!read(teb+0x30,peb)||!peb||!read(peb+2,savedPeb)){log("Cannot read the x32 PEB");disarm();return false;}
  pebFlag=peb+2;if(!write(pebFlag,static_cast<unsigned char>(0))){disarm();return false;}
  BOOL wow=FALSE;if(!IsWow64Process(DbgGetProcessHandle(),&wow)){disarm();return false;}
  if(wow){
   const auto nativePeb=KozWow64::targetPeb(DbgGetProcessHandle());unsigned char zero=0;
   if(!nativePeb||!KozWow64::readTarget(DbgGetProcessHandle(),nativePeb+2,&savedNativePeb,1)){log("Cannot read native WOW64 PEB");disarm();return false;}
   nativePebFlag=nativePeb+2;
   if(!KozWow64::writeTarget(DbgGetProcessHandle(),nativePebFlag,&zero,1)){log("Cannot hide native WOW64 PEB debugger flag");disarm();return false;}
   log("PEB debugger flags hidden in both x32 and native WOW64 views");
  }
 }
 armed=true;log("x32 profile armed. Profiles 360/380/394/3101 include WOW64 syscall handling.");return true;
}
static bool finish(duint pc,duint sp,unsigned argCount,duint value){
 uint32_t after=0;if(!kozX86ReturnStack(sp,argCount,after))return false;
 return R::SetEAX(value)&&R::SetESP(after)&&R::SetEIP(pc);
}
static bool watch(duint pc,duint sp,unsigned count,duint buffer,unsigned action,duint size=0){
 uint32_t after=0;if(pending.size()>=4096||!kozX86ReturnStack(sp,count,after))return false;
 if(!addBinding(pc,99))return false;
 pending.push_back({pc,after,buffer,DbgGetThreadId(),action,size});return true;
}
static bool hit(int argc,char** argv){
 if(!armed||argc!=2)return true;
 unsigned action=0;if(sscanf_s(argv[1],"%u",&action)!=1)return false;
 const duint ip=R::GetEIP(),sp=R::GetESP();bool ok=true;
 if(action==18){
  duint ra=0,output=0,attributes=0,iosb=0,lengthAddress=0;uint16_t length=0;
  ok=read(sp,ra)&&read(sp+4,output)&&read(sp+12,attributes)&&read(sp+16,iosb);
  if(ok&&gateTitanName(output,attributes,iosb,lengthAddress,length)){ok=finish(ra,sp,6,0xc0000034);if(ok)++hits[11];}
 }else if(action==19){
  duint ra=0,handle=0,info=0,buffer=0,size=0;
  ok=read(sp,ra)&&read(sp+4,handle)&&read(sp+8,info)&&read(sp+12,buffer)&&read(sp+16,size);
  if(ok&&on(3)&&info==0x11&&size==1&&self(handle,true)&&
   std::find(gateHiddenThreads.begin(),gateHiddenThreads.end(),gateThreadId(handle))!=gateHiddenThreads.end())ok=watch(ra,sp,5,buffer,18);
 }else if(action==17){ok=gateReturn();
 }else if(action==11){log("Obsolete gate binding; reapply the profile to remove it");ok=false;
 }else if(action==12){
  KozWow64::Context gate;
  ok=gateProfile()&&KozWow64::get(DbgGetThreadHandle(),gate)&&gate.q(248)<=UINT32_MAX;
  if(ok&&nativeOwnGate(static_cast<duint>(gate.q(248))))ok=gateBegin(static_cast<duint>(gate.q(248)),DbgGetThreadHandle());
 }else if(action==13||action==14){
  if(nativeHardwareStepThread==DbgGetThreadId())return true;
  KozWow64::Context c;const HANDLE thread=DbgGetThreadHandle();
  ok=advancedProfile()&&KozWow64::get(thread,c)&&c.q(248)<=UINT32_MAX;
  if(ok){
   const auto pc=static_cast<duint>(c.q(248));
   ok=action==13?nativeOwnGateGuard(pc):nativeOwnGuard(pc);
   const bool returned=gateProfile()&&nativeWindow&&nativeWindowEntered&&(c.d(56)&0xffff)==0x23;
   if(ok&&returned)ok=endNativeWindow(pc);
   if(ok&&action==13){
    ok=armNativeHardwarePage(pc,thread,true);
    if(ok&&(c.d(56)&0xffff)==0x23&&std::find(nativeGateSites.begin(),nativeGateSites.end(),pc)!=nativeGateSites.end())ok=gateBegin(pc,thread);
   }else if(ok&&!returned)ok=ensureNativeCoverage(pc,thread);
   if(ok&&(c.d(56)&0xffff)==0x33){
    if(nativeWindow)nativeWindowEntered=true;
    ok=handleNative(thread);
   }
  }
 }else if(action==10){ok=handleNative();
 }else if(action==16){
  if(on(10)&&on(0))ok=Script::Flag::SetZF(false);
 }else if(action==15){
  duint ra=0,process=0,destination=0,size=0;
  ok=read(sp,ra)&&sp<=UINT32_MAX-20&&read(sp+4,process)&&read(sp+8,destination)&&read(sp+16,size);
  if(ok&&on(10)&&breakinAddress&&breakinPid==GetProcessId(DbgGetProcessHandle())&&self(process)&&size&&destination<=UINT32_MAX-size){
   const duint begin=std::max(destination,breakinAddress),end=std::min(destination+size,breakinAddress+static_cast<duint>(breakinBytes.size()));
   if(begin<end)ok=watch(ra,sp,5,begin,15,end-begin);
  }
 }else if(action==9){
  duint ra=0,process=0,info=0,buffer=0,length=0;std::array<uint32_t,3> data{};
  if(read(sp,ra)&&read(sp+4,process)&&read(sp+8,info)&&read(sp+12,buffer)&&read(sp+16,length)&&self(process)&&info==0x28&&length==12&&!(buffer&3)&&read(buffer,data)&&data==std::array<uint32_t,3>{}){
   ok=finish(ra,sp,4,0);if(ok){++hits[8];log("x32 null instrumentation callback clearing suppressed");}
  }
 }else if(action==7){
  duint recordAddress=0,address=0;EXCEPTION_RECORD record{};CONTEXT context{};
  if(!read(sp,recordAddress)||!read(sp+4,address)||!read(recordAddress,record)||!read(address,context))ok=false;
  else{
   if(tfDeliveryPending&&record.ExceptionCode==EXCEPTION_SINGLE_STEP&&trustedTf(reinterpret_cast<duint>(record.ExceptionAddress))){
    _plugin_debugskipexceptions(false);tfDeliveryPending=false;
    log("Recognized TF reached dispatch; normal exception handling restored");
   }
   if(on(9)&&record.ExceptionCode==EXCEPTION_SINGLE_STEP&&trustedTf(reinterpret_cast<duint>(record.ExceptionAddress))&&
   context.Eip==reinterpret_cast<duint>(record.ExceptionAddress)&&(context.ContextFlags&CONTEXT_DEBUG_REGISTERS)==CONTEXT_DEBUG_REGISTERS&&
   (context.Dr0|context.Dr1|context.Dr2|context.Dr3)){
   if(contexts.size()>=128)ok=false;
   else{
    const std::array<DWORD,4> zero{};
    contexts.push_back({DbgGetThreadId(),address,context.Eip,{context.Dr0,context.Dr1,context.Dr2,context.Dr3}});
    ok=DbgMemWrite(address+offsetof(CONTEXT,Dr0),zero.data(),sizeof(zero));
    if(ok){++hits[9];tfWindowEvents=0;log("Saved x32 DR0-DR3 hidden for TF handler; live slots untouched");}
   }
  }
  }
 }else if(action==8){
  duint address=0;if(!read(sp+4,address))ok=false;
  else{
   auto it=std::find_if(contexts.rbegin(),contexts.rend(),[&](const SavedContext& c){return c.thread==DbgGetThreadId()&&c.address==address;});
   if(it!=contexts.rend()){
    std::array<DWORD,4> current{};
    ok=DbgMemRead(address+offsetof(CONTEXT,Dr0),current.data(),sizeof(current));
    if(ok&&current==std::array<DWORD,4>{})ok=DbgMemWrite(address+offsetof(CONTEXT,Dr0),it->dr.data(),sizeof(it->dr));
    if(ok){contexts.erase(std::next(it).base());log("Saved x32 DR0-DR3 restored before NtContinue");}
   }
  }
 }else if(action==99){
  auto it=std::find_if(pending.begin(),pending.end(),[&](const Pending& p){return p.address==ip&&p.stack==sp&&p.thread==DbgGetThreadId();});
  if(it==pending.end())return true;
  const auto p=*it;pending.erase(it);
  const auto result=R::GetEAX();log("Return action=%u pc=%08X result=%08X buffer=%08X",p.action,ip,result,p.buffer);
  if(p.action==18){if(static_cast<int32_t>(result)>=0){ok=write(p.buffer,static_cast<unsigned char>(1));if(ok)++hits[3];}}
  else if(p.action==1){if(result){ok=write(p.buffer,uint32_t(0));if(ok)++hits[1];}}
  else if(p.action==15){
   if(result){
    const auto offset=p.buffer-breakinAddress;
    ok=breakinPid==GetProcessId(DbgGetProcessHandle())&&offset<breakinBytes.size()&&p.size<=breakinBytes.size()-offset&&
     DbgMemWrite(p.buffer,breakinBytes.data()+offset,p.size)&&FlushInstructionCache(DbgGetProcessHandle(),reinterpret_cast<void*>(p.buffer),p.size);
    if(ok){++hits[10];log("Restored DbgUiRemoteBreakin after self-write: %08X, %u bytes",p.buffer,p.size);}
   }
  }
  else if(static_cast<int32_t>(result)>=0){
   if(p.action==5){
    uint32_t count=0;ok=p.size>=4&&read(p.buffer,count)&&count<65536&&count<=(p.size-4)/0x11c;
    if(ok){
     std::vector<unsigned char> data(static_cast<size_t>(count)*0x11c);uint32_t kept=0;
     ok=data.empty()||DbgMemRead(p.buffer+4,data.data(),data.size());
     for(uint32_t i=0;ok&&i<count;i++){
      auto record=data.data()+i*0x11c;uint16_t offset=0;memcpy(&offset,record+0x1a,2);
      if(offset>=256||!memchr(record+0x1c+offset,0,256-offset)){ok=false;break;}
      bool remove=false;for(auto name:{"sice.sys","siwvid.sys","ntice.sys","iceext.sys","syser.sys"})if(_stricmp(reinterpret_cast<char*>(record+0x1c+offset),name)==0)remove=true;
      if(!remove){if(kept!=i)memmove(data.data()+kept*0x11c,record,0x11c);++kept;}
     }
     if(ok&&kept<count){std::fill(data.begin()+kept*0x11c,data.end(),static_cast<unsigned char>(0));ok=DbgMemWrite(p.buffer+4,data.data(),data.size())&&write(p.buffer,kept);}
     if(ok){++hits[5];log("x32 driver list: %u entries, %u filtered",count,count-kept);}
    }
   }else if(p.action==4)ok=write(p.buffer,uint16_t(0x100));
   else ok=write(p.buffer,uint32_t(p.action==3?1:0));
   if(ok&&p.action!=5)++hits[p.action==4?4:1];
  }
  if(std::none_of(pending.begin(),pending.end(),[&](const Pending& p){return p.address==ip;})){
   auto b=std::find_if(owned.begin(),owned.end(),[&](const Binding& b){return b.address==ip&&b.action==99;});
   if(b!=owned.end()){if(removeBinding(*b))owned.erase(b);else ok=false;}
  }
 }else{
  duint ra=0;std::array<duint,5> a{};
  const unsigned counts[]={0,2,5,4,4,1};
  if(action>=6||!read(sp,ra)||sp>UINT32_MAX-24){log("Cannot read x32 API frame; target paused");cmd("mov $breakpointcondition,1");return false;}
  for(unsigned i=0;i<counts[action];i++)if(!read(sp+4*(i+1),a[i])){ok=false;break;}
  if(ok&&Script::Module::BaseFromAddr(ra)==Script::Module::GetMainModuleBase())log("API %u pc=%08X ra=%08X args=%08X,%08X,%08X,%08X,%08X",action,ip,ra,a[0],a[1],a[2],a[3],a[4]);
  if(ok)switch(action){
   case 0:ok=R::SetEAX(0);if(ok)++hits[0];break;
   case 1:if(self(a[0])&&a[1])ok=watch(ra,sp,2,a[1],1);break;
   case 2:
    if(self(a[0])&&a[3]==4&&!(a[2]&3)){
     if(a[1]==0x1e&&on(2)&&writable(a[2],4)&&(!a[4]||(!(a[4]&3)&&writable(a[4],4)))){
      ok=write(a[2],uint32_t(0))&&(!a[4]||write(a[4],uint32_t(4)))&&finish(ra,sp,5,0xc0000353);if(ok)++hits[2];
     }else if(on(1)&&(a[1]==7||a[1]==0x1f))ok=watch(ra,sp,5,a[2],a[1]==7?2:3);
    }break;
   case 3:if(a[1]==0x11&&!a[2]&&!a[3]&&self(a[0],true)){ok=finish(ra,sp,4,0);if(ok){++hits[3];if(extendedChecks()){const auto id=gateThreadId(a[0]);if(id&&std::find(gateHiddenThreads.begin(),gateHiddenThreads.end(),id)==gateHiddenThreads.end())gateHiddenThreads.push_back(id);}}}break;
   case 4:if(on(4)&&a[0]==0x23&&a[1]&&a[2]>=2)ok=watch(ra,sp,4,a[1],4);
    else if(on(5)&&a[0]==0xb&&a[1]&&a[2]>=4)ok=watch(ra,sp,4,a[1],5,a[2]);break;
   case 5:if(a[0]==0xdeadc0de){ok=gateFinishStartup()&&finish(ra,sp,1,0xc0000008);if(ok)++hits[6];}break;
  }
 }
 if(!ok){log("API handling failed at %08X; target paused",ip);cmd("mov $breakpointcondition,1");}return ok;
}
static duint nativeCondition(int argc,const duint* argv,void*){
 if(argc!=1||(argv[0]!=10&&argv[0]!=12&&argv[0]!=13&&argv[0]!=14&&argv[0]!=17))return 1;
 // The engine has already identified our breakpoint. Successful maintenance
 // can use its fast-resume path without interrupting GUI scripts on every hit.
 auto number=std::to_string(argv[0]);char name[]="kz32_hit";char* args[]={name,&number[0]};
 return hit(2,args)?0:1;
}
static bool status(int,char**){log("x32 profile=%u | armed=%s | controls=%X",profile.load(),armed?"yes":"no",options.load());for(unsigned i=0;i<hits.size();i++)log("Control %u hits=%u",i,hits[i].load());return true;}
static bool select(int argc,char** argv){
 if(argc!=2|| (strcmp(argv[1],"331")&&strcmp(argv[1],"340")&&strcmp(argv[1],"350")&&strcmp(argv[1],"360")&&strcmp(argv[1],"380")&&strcmp(argv[1],"394")&&strcmp(argv[1],"3101")&&strcmp(argv[1],"off"))){log("Usage: kz_profile 331 | 340 | 350 | 360 | 380 | 394 | 3101 | off (shared x32 API backend)");return false;}
 if(DbgIsDebugging()&&DbgIsRunning())return false;
 if(!disarm())return false;if(!save())return false;enabled=strcmp(argv[1],"off")!=0;
 if(enabled){profile=static_cast<unsigned>(atoi(argv[1]));options=profileOptions(profile);}
 updateMenu();return apply(0,nullptr)&&save();
}
static bool configure(int argc,char** argv){
 unsigned value=0,autoValue=0,id=profile.load();if((argc!=3&&argc!=4)||sscanf_s(argv[1],"%u",&value)!=1||sscanf_s(argv[2],"%u",&autoValue)!=1||value>supportedMask||autoValue>1)return false;
 if(DbgIsDebugging()&&DbgIsRunning())return false;
 if(argc==4&&(sscanf_s(argv[3],"%u",&id)!=1||!findProfile(id)))return false;
 if(!disarm())return false;if(id!=profile&&!save())return false;profile=id;options=value&profileMask(id);automatic=autoValue!=0;updateMenu();return apply(0,nullptr)&&save();
}
static INT_PTR CALLBACK dialog(HWND wnd,UINT msg,WPARAM wp,LPARAM){
 if(msg==WM_INITDIALOG){
  settingsWindow=wnd;SetWindowTextW(wnd,L"KozDbg x32");
  SendMessageW(wnd,WM_SETICON,ICON_SMALL,reinterpret_cast<LPARAM>(LoadIconW(instance,MAKEINTRESOURCEW(102))));
  for(unsigned i=0;i<sizeof(profiles)/sizeof(profiles[0]);i++){SendDlgItemMessageW(wnd,110,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(profiles[i].wide));if(profiles[i].id==profile)SendDlgItemMessageW(wnd,110,CB_SETCURSEL,i,0);}
  CheckDlgButton(wnd,111,automatic?BST_CHECKED:BST_UNCHECKED);
  tooltip=CreateWindowExW(WS_EX_TOPMOST,TOOLTIPS_CLASSW,nullptr,WS_POPUP|TTS_ALWAYSTIP,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,wnd,nullptr,instance,nullptr);
  SendMessageW(tooltip,TTM_SETMAXTIPWIDTH,0,360);
  static const wchar_t* descriptions[]={L"32-bit PEB.BeingDebugged and IsDebuggerPresent",L"CheckRemoteDebuggerPresent, ProcessDebugPort and ProcessDebugFlags",L"ProcessDebugObjectHandle query",L"ThreadHideFromDebugger through the x32 Nt API",L"SystemKernelDebuggerInformation query",L"Filters the five researched debugger driver names from x32 module queries",L"The DEADC0DE invalid-handle probe",L"Delivers the recognized POPFD/RDTSC/NOP exception to the target"};
  for(unsigned i=0;i<13;i++){
   EnableWindow(GetDlgItem(wnd,120+i),(profileMask(profile)&(1u<<i))!=0);CheckDlgButton(wnd,120+i,on(i)?BST_CHECKED:BST_UNCHECKED);
   TOOLINFOW tool{};tool.cbSize=sizeof(tool);tool.uFlags=TTF_IDISHWND|TTF_SUBCLASS;tool.hwnd=wnd;tool.uId=reinterpret_cast<UINT_PTR>(GetDlgItem(wnd,201+i));tool.lpszText=const_cast<wchar_t*>((i<8?descriptions[i]:i==8?L"Preserves the existing null instrumentation callback state":i==9?L"Hides saved DR0-DR3 during the recognized TF handler, restores at NtContinue":i==10?L"Restores DbgUiRemoteBreakin after successful self-process WriteProcessMemory calls":i==11?L"Blocks the exact TitanHide device open; no driver required":L"Not implemented in the x32 backend"));SendMessageW(tooltip,TTM_ADDTOOLW,0,reinterpret_cast<LPARAM>(&tool));
  }return TRUE;
 }
 if(msg==WM_COMMAND){
  if(LOWORD(wp)==110&&HIWORD(wp)==CBN_SELCHANGE){
   const auto index=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);
   if(index>=0&&index<static_cast<LRESULT>(sizeof(profiles)/sizeof(profiles[0]))){const auto value=profileOptions(profiles[index].id);for(unsigned i=0;i<13;i++){EnableWindow(GetDlgItem(wnd,120+i),(profileMask(profiles[index].id)&(1u<<i))!=0);CheckDlgButton(wnd,120+i,(value&(1u<<i))?BST_CHECKED:BST_UNCHECKED);}}return TRUE;
  }
  if(LOWORD(wp)==IDCANCEL){EndDialog(wnd,0);return TRUE;}
  if(LOWORD(wp)==150){MessageBoxW(wnd,L"KozDbg x32\nIvan Kozlovsky\ncontact@ivankozlovsky.com\nivankozlovsky.com\nMIT license\n\nAPI backend tested with x32 RiddleGame on 3.3.1, 3.4.0 and 3.5.0.\n3.6 tested with x32 RiddleGame. 3.8 automatic GUI verified. 3.9.4 and 3.10.1 automatic GUI verified on the supplied RiddleGame samples.",L"About KozDbg",MB_OK);return TRUE;}
  if(LOWORD(wp)==151){ShellExecuteW(wnd,L"open",L"notepad.exe",(L"\""+iniPath+L"\"").c_str(),nullptr,SW_SHOWNORMAL);return TRUE;}
  if(LOWORD(wp)==IDOK){
   if(DbgIsDebugging()&&DbgIsRunning()){MessageBoxW(wnd,L"Pause the target first.",L"KozDbg",MB_OK);return TRUE;}
   unsigned value=0;for(unsigned i=0;i<12;i++)if(IsDlgButtonChecked(wnd,120+i)==BST_CHECKED)value|=1u<<i;
   const auto index=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);if(index<0||index>=static_cast<LRESULT>(sizeof(profiles)/sizeof(profiles[0])))return TRUE;
   const auto request="kz32_config "+std::to_string(value&profileMask(profiles[index].id))+","+(IsDlgButtonChecked(wnd,111)==BST_CHECKED?"1":"0")+","+std::to_string(profiles[index].id);
   if(DbgCmdExec(request.c_str()))EndDialog(wnd,1);return TRUE;
  }
 }
 if(msg==WM_DESTROY){if(tooltip)DestroyWindow(tooltip);tooltip=nullptr;settingsWindow=nullptr;}return FALSE;
}
static void show(){if(settingsWindow){SetForegroundWindow(settingsWindow);return;}DialogBoxParamW(instance,MAKEINTRESOURCEW(101),owner,dialog,0);}
static bool settings(int,char**){GuiExecuteOnGuiThread(show);return true;}
static void callback(CBTYPE type,void* info){
 // 3.8 observes x86 transition boundaries. Its native interval has no page
 // guards, so it does not need the 3.6 native-context repair on every event.
 if(type==CB_DEBUGEVENT&&armed&&profile==360&&nativePhase){
  const auto event=static_cast<PLUG_CB_DEBUGEVENT*>(info)->DebugEvent;
  if(event->dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)log("Target exit: %08X",event->u.ExitProcess.dwExitCode);
  if(event->dwDebugEventCode==EXCEPTION_DEBUG_EVENT){
   const HANDLE thread=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,event->dwThreadId);
   KozWow64::Context c;
   if(thread&&KozWow64::get(thread,c)){
    const auto& stepRecord=event->u.Exception.ExceptionRecord;
    // TitanEngine temporarily removes a hit hardware slot until its internal
    // single-step completes. Its breakpoint database still owns that slot.
    // Do not rotate or re-enable it during an intervening execute-page fault.
    if(nativeHardwareStepThread==event->dwThreadId){
     if(stepRecord.ExceptionCode==EXCEPTION_SINGLE_STEP){
      nativeHardwareStepThread=0;
      if((c.d(56)&0xffff)==0x33){
       const bool internalStep=(c.q(104)&0x4000)&&!(c.q(104)&0xf);
       c.d(68,c.d(68)&~0x100u);
       if(!KozWow64::set(thread,c))log("Cannot finish native hardware step");
       else if(internalStep&&event->u.Exception.dwFirstChance){
        nativeGuardThread=event->dwThreadId;
        nativeGuardIp=reinterpret_cast<duint>(stepRecord.ExceptionAddress);
        nativeGuardCode=stepRecord.ExceptionCode;
        log("Completed plugin-owned native hardware step at %llX",c.q(248));
       }
      }
     }
     CloseHandle(thread);return;
    }
    const bool ownHardwareHit=stepRecord.ExceptionCode==EXCEPTION_SINGLE_STEP&&(c.q(104)&0xf)&&
     nativeOwnHardware(reinterpret_cast<duint>(stepRecord.ExceptionAddress));
    if(!reconcileRetiredNativeSlots(thread,c))log("Retired native DR context synchronization failed");
    static unsigned diagnostic=0;if(diagnostic++<12)log("WOW64 event code=%08X nativeCS=%X nativeIP=%llX",event->u.Exception.ExceptionRecord.ExceptionCode,c.d(56)&0xffff,c.q(248));
    const auto& record=event->u.Exception.ExceptionRecord;
    if(!contexts.empty()&&tfWindowEvents++<16)log("TF handler event: code=%08X first=%u IP=%p CS=%X nativeIP=%llX access=%llu fault=%llu",record.ExceptionCode,event->u.Exception.dwFirstChance,record.ExceptionAddress,c.d(56)&0xffff,c.q(248),static_cast<unsigned long long>(record.ExceptionInformation[0]),static_cast<unsigned long long>(record.ExceptionInformation[1]));
    if(nativeWindow&&nativeWindowEvents++<12)log("Window event: code=%08X CS=%X IP=%llX fault=%p info=%llu",record.ExceptionCode,c.d(56)&0xffff,c.q(248),record.ExceptionAddress,static_cast<unsigned long long>(record.ExceptionInformation[0]));
    // Execute-page exceptions are consumed by TitanEngine before commands
    // 13/14 promote the page. Removing them here would bypass exception filters.
    if((c.d(56)&0xffff)==0x33&&record.ExceptionCode==EXCEPTION_SINGLE_STEP){nativeSeen=true;
     const auto ip=c.q(248);
     if(ip<=UINT32_MAX&&(std::find(nativeSites.begin(),nativeSites.end(),static_cast<duint>(ip))!=nativeSites.end()||(ip&&std::find(nativeSites.begin(),nativeSites.end(),static_cast<duint>(ip-1))!=nativeSites.end()))){
      if(nativeWindow)nativeWindowEntered=true;
      bool completed=false;
      log("Native event %08X rip=%llX",event->u.Exception.ExceptionRecord.ExceptionCode,ip);if(!handleNative(thread,&completed))log("Native event handling failed");
      if(completed&&nativeOwnHardware(static_cast<duint>(ip))){nativeGuardThread=event->dwThreadId;nativeGuardIp=reinterpret_cast<duint>(record.ExceptionAddress);nativeGuardCode=record.ExceptionCode;}
     }
    }
    if(ownHardwareHit){
     nativeHardwareStepThread=event->dwThreadId;
     KozWow64::Context after;
     if(KozWow64::get(thread,after)&&(after.d(56)&0xffff)==0x33){
      after.d(68,after.d(68)|0x100u);
      if(!KozWow64::set(thread,after))log("Cannot arm native hardware single-step");
     }
    }
   }
   if(thread)CloseHandle(thread);
  }
 }
 if(type==CB_EXCEPTION&&armed&&nativeGuardThread){
  const auto ex=static_cast<PLUG_CB_EXCEPTION*>(info)->Exception;
  const bool ours=ex->dwFirstChance&&DbgGetThreadId()==nativeGuardThread&&
   reinterpret_cast<duint>(ex->ExceptionRecord.ExceptionAddress)==nativeGuardIp&&ex->ExceptionRecord.ExceptionCode==nativeGuardCode;
  nativeGuardThread=0;
  if(ours){DbgCmdExec("serun");return;}
 }
 if(type==CB_EXCEPTION&&armed&&on(7)){
  const auto ex=static_cast<PLUG_CB_EXCEPTION*>(info)->Exception;
  duint popped=0;const duint ip=reinterpret_cast<duint>(ex->ExceptionRecord.ExceptionAddress);
  if(ex->dwFirstChance&&ex->ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP&&trustedTf(ip)&&
   R::GetESP()>=4&&read(R::GetESP()-4,popped)&&(popped&0x100)&&!(R::GetDR6()&0xf)){
   ++hits[7];tfDeliveryPending=true;log("Delivering recognized x32 POPFD/RDTSC/NOP exception");DbgCmdExec("erun");
  }
 }
 if(type==CB_SYSTEMBREAKPOINT&&enabled&&automatic)DbgCmdExec("kz_apply");
 if(type==CB_INITDEBUG){gateCall={};gateHiddenThreads.clear();breakinPid=0;breakinAddress=0;nativePhase=false;nativeSeen=false;nativeHardwareStepThread=0;nativePageProtections.clear();retiredNativeSlots.clear();owned.clear();pending.clear();contexts.clear();pebFlag=0;nativePebFlag=0;targetPid=0;armed=false;for(auto& n:hits)n=0;}
 if(type==CB_STOPPINGDEBUG||type==CB_DETACH)disarm();
 if(type==CB_EXITTHREAD){
  const DWORD id=static_cast<PLUG_CB_EXITTHREAD*>(info)->dwThreadId;
  gateHiddenThreads.erase(std::remove(gateHiddenThreads.begin(),gateHiddenThreads.end(),id),gateHiddenThreads.end());
  contexts.erase(std::remove_if(contexts.begin(),contexts.end(),[&](const SavedContext& c){return c.thread==id;}),contexts.end());
  pending.erase(std::remove_if(pending.begin(),pending.end(),[&](const Pending& p){return p.thread==id;}),pending.end());
  kozRetryCleanup(owned,[](const Binding& b){
   if(b.action!=99||std::any_of(pending.begin(),pending.end(),[&](const Pending& p){return p.address==b.address;}))return false;
   return removeBinding(b);
  });
 }
 if(type==CB_STOPDEBUG){owned.clear();pending.clear();pebFlag=0;armed=false;}
 if(type==CB_MENUENTRY){switch(static_cast<PLUG_CB_MENUENTRY*>(info)->hEntry){
  case 1:DbgCmdExec("kz_profile 331");break;case 7:DbgCmdExec("kz_profile 340");break;case 8:DbgCmdExec("kz_profile 350");break;case 9:DbgCmdExec("kz_profile 360");break;case 10:DbgCmdExec("kz_profile 380");break;case 11:DbgCmdExec("kz_profile 394");break;case 12:DbgCmdExec("kz_profile 3101");break;case 2:DbgCmdExec("kz_profile off");break;
  case 3:settings(0,nullptr);break;case 4:DbgCmdExec("kz_apply");break;
  case 5:automatic=!automatic;updateMenu();save();break;case 6:DbgCmdExec("kz_status");break;
 }}
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init){
 init->sdkVersion=PLUG_SDKVERSION;init->pluginVersion=111;pluginHandle=init->pluginHandle;strcpy_s(init->pluginName,"KozDbg x32");
 std::vector<wchar_t> path(32768);const DWORD size=GetModuleFileNameW(instance,path.data(),static_cast<DWORD>(path.size()));if(!size||size>=path.size())return false;iniPath.assign(path.data(),size);iniPath+=L".ini";
 enabled=GetPrivateProfileIntW(L"Settings",L"Enabled",1,iniPath.c_str())!=0;automatic=GetPrivateProfileIntW(L"Settings",L"AutoArm",1,iniPath.c_str())!=0;profile=GetPrivateProfileIntW(L"Settings",L"Profile",331,iniPath.c_str());if(!findProfile(profile))profile=331;options=profileOptions(profile);
 if(!_plugin_registerexprfunction(pluginHandle,"kz32_native",1,nativeCondition,nullptr))return false;
 _plugin_registercommand(pluginHandle,"kz_apply",apply,false);_plugin_registercommand(pluginHandle,"kz_status",status,false);_plugin_registercommand(pluginHandle,"kz_settings",settings,false);_plugin_registercommand(pluginHandle,"kz_profile",select,false);_plugin_registercommand(pluginHandle,"kz32_config",configure,false);_plugin_registercommand(pluginHandle,"kz32_hit",hit,true);
 for(auto type:{CB_MENUENTRY,CB_SYSTEMBREAKPOINT,CB_INITDEBUG,CB_STOPPINGDEBUG,CB_STOPDEBUG,CB_DETACH,CB_EXITTHREAD,CB_EXCEPTION,CB_DEBUGEVENT})_plugin_registercallback(pluginHandle,type,callback);
 log("x32 backend loaded v1.1.1. Profiles 360/380/394/3101 WOW64 support is enabled. x64 INI files are not used.");return true;
}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup){
 owner=setup->hwndDlg;
 const HRSRC resource=FindResourceW(instance,MAKEINTRESOURCEW(103),RT_RCDATA);
 if(resource){const HGLOBAL data=LoadResource(instance,resource);ICONDATA icon{};icon.data=data?LockResource(data):nullptr;icon.size=SizeofResource(instance,resource);if(icon.data)_plugin_menuseticon(setup->hMenu,&icon);}
 for(const auto& p:profiles)_plugin_menuaddentry(setup->hMenu,p.menu,p.label);_plugin_menuaddentry(setup->hMenu,2,"Disabled");_plugin_menuaddseparator(setup->hMenu);
 _plugin_menuaddentry(setup->hMenu,3,"Settings...");_plugin_menuaddentry(setup->hMenu,4,"Apply to paused session");_plugin_menuaddentry(setup->hMenu,5,"Auto-arm on start");_plugin_menuaddentry(setup->hMenu,6,"Session log");menuReady=true;updateMenu();
}
extern "C" __declspec(dllexport) bool plugstop(){
 if(settingsWindow||(DbgIsDebugging()&&DbgIsRunning())||!disarm())return false;
 _plugin_unregisterexprfunction(pluginHandle,"kz32_native");
 for(auto name:{"kz_apply","kz_status","kz_settings","kz_profile","kz32_config","kz32_hit"})_plugin_unregistercommand(pluginHandle,name);return true;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){instance=module;DisableThreadLibraryCalls(module);}return TRUE;}
