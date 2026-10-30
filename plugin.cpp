#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <deque>
#include <_plugins.h>
#include <_scriptapi_register.h>
#include <_scriptapi_module.h>
#include <array>
#include <atomic>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <limits>
#include <map>
#include <mutex>
#include "retry_cleanup.h"
#include "profile_transition.h"
#include "status_snapshot.h"
#include "ini_writer.h"

namespace R = Script::Register;
namespace M = Script::Module;
static HINSTANCE instance;
static HWND owner;
static int pluginHandle;
static std::wstring iniPath;
static std::wstring profilesPath;
static std::wstring logPath;
static std::atomic<bool> enabled{true}, autoArm{true}, armed{false};
enum class Engine { Api, ClusteredSyscalls, ScatteredSyscalls };
struct Profile {const char* key;const char* version;const char* menu;const wchar_t* label;int menuId;Engine engine;bool extended=false;};
static std::vector<Profile> profiles{
 {"331","3.3.1","VMProtect 3.3.1",L"VMProtect 3.3.1 - x64",1,Engine::Api},
 {"340","3.4.0","VMProtect 3.4.0",L"VMProtect 3.4.0 - x64",7,Engine::Api},
 {"350","3.5.0","VMProtect 3.5.0",L"VMProtect 3.5.0 - x64",8,Engine::Api},
 {"360","3.6","VMProtect 3.6",L"VMProtect 3.6 - x64",9,Engine::ClusteredSyscalls},
 {"380","3.8.0","VMProtect 3.8.0",L"VMProtect 3.8.0 - x64",10,Engine::ScatteredSyscalls},
 {"394","3.9.4","VMProtect 3.9.4",L"VMProtect 3.9.4 - x64",11,Engine::ScatteredSyscalls,true},
 {"3101","3.10.1","VMProtect 3.10.1",L"VMProtect 3.10.1 - x64",12,Engine::ScatteredSyscalls,true}
};
static std::atomic<unsigned> selectedProfile{0};
static const Profile& profile(){return profiles[selectedProfile.load()];}
static bool advanced(){return profile().engine!=Engine::Api;}
static bool extendedChecks(){return profile().extended;}
static constexpr unsigned controlCount=13;
static std::atomic<unsigned> mask{8191};
static std::array<std::atomic<unsigned>,controlCount> hits{};
static std::array<std::atomic<unsigned>,13> apiSeen{};
static std::vector<duint> owned;
static bool setupDone;
static HWND settingsWindow;
static HWND settingsTooltips;
enum class ReturnKind { Remote, Kernel, Modules, Attach, HiddenThread };
static std::vector<DWORD> hiddenThreads;
struct Pending {duint address, buffer, size, stack; DWORD thread; ReturnKind kind;};
static std::vector<Pending> pending;
static bool setupDirect();
static bool setupLegacyContext();
static bool disarmDirect();
static bool hitDirect(int action,duint ip,duint sp,duint ra);
static bool syscallHit(int,char**);
static bool restoreAttach();
static bool prepareTfWindow(duint returnAddress);
static void dropSavedContexts(DWORD thread);
static bool clearModuleHardware();
static void moduleHardwareEvent(CBTYPE type,void* info);
static bool moduleHardwareTail(DWORD process,DWORD thread);
static bool installDebugEventTail();
static bool removeDebugEventTail();
static bool emulateQuery(duint process,duint infoClass,duint buffer,duint size,duint returnLength,duint& status);

static std::string hex(duint x) {char s[32]; sprintf_s(s,"%llX",(unsigned long long)x);return s;}
static bool cmd(const std::string& c) {return DbgCmdExecDirect(c.c_str());}
static void logf(const char* format,...) {
 char text[4096];va_list args;va_start(args,format);vsnprintf_s(text,sizeof(text),_TRUNCATE,format,args);va_end(args);
 _plugin_logputs(text);
 HANDLE file=CreateFileW(logPath.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
 if(file!=INVALID_HANDLE_VALUE){DWORD written=0;WriteFile(file,text,static_cast<DWORD>(strlen(text)),&written,nullptr);CloseHandle(file);}
}
static void log(const char* s) {logf("[KozDbg] %s\n",s);}
// Only successful, explicitly selected informational events use this path.
// Errors and warnings continue to use log/logf and are never deduplicated.
static std::mutex infoLogMutex;
static std::map<std::string,unsigned long long> infoLogCounts;
static bool firstInfo(const char* key) {
 std::lock_guard<std::mutex> lock(infoLogMutex);
 return ++infoLogCounts[key]==1;
}
static void info(const char* text) {if(firstInfo(text))log(text);}
static void infof(const char* key,const char* format,...) {
 if(!firstInfo(key))return;
 char text[4096];va_list args;va_start(args,format);vsnprintf_s(text,sizeof(text),_TRUNCATE,format,args);va_end(args);
 logf("%s",text);
}
static void resetInfoCounts() {std::lock_guard<std::mutex> lock(infoLogMutex);infoLogCounts.clear();}
static void printInfoCounts() {
 std::map<std::string,unsigned long long> snapshot;
 {std::lock_guard<std::mutex> lock(infoLogMutex);snapshot=infoLogCounts;}
 log("Information totals: first occurrence printed; subsequent occurrences counted only.");
 for(const auto& entry:snapshot)logf("  total=%llu repeats=%llu | %s\n",entry.second,entry.second-1,entry.first.c_str());
}
static bool on(unsigned n) {return (mask.load()&(1u<<n))!=0;}
template<class T> static bool read(duint p,T& value) {return DbgMemRead(p,&value,sizeof(value));}
template<class T> static bool write(duint p,const T& value) {return DbgMemWrite(p,&value,sizeof(value));}
static void count(unsigned n,const char* text) {++hits[n];info(text);}
static bool ret(duint address,duint result) {
 // No instruction patch or injected code: emulate a normal x64 leaf return.
 return R::SetRAX(result)&&R::SetRSP(R::GetRSP()+8)&&R::SetRIP(address);
}
static void updateMenu() {
 if(!setupDone)return;
 for(unsigned i=0;i<profiles.size();i++)_plugin_menuentrysetchecked(pluginHandle,profiles[i].menuId,enabled&&selectedProfile==i);
 _plugin_menuentrysetchecked(pluginHandle,2,!enabled);
 _plugin_menuentrysetchecked(pluginHandle,5,autoArm);
}
#include "profiles.inl"
static void settingsSaveError(){
 MessageBoxW(owner,L"Could not save all settings. Runtime settings may already be applied, but disk settings may be incomplete. See the log for the file, section, key and Windows error. Fix file permissions and save again.",L"KozDbg - settings not saved",MB_OK|MB_ICONERROR);
}
static bool saveSettings() {
 KozIniWriter writer;
 writer.put(iniPath,L"Settings",L"Enabled",enabled?L"1":L"0");
 writer.put(iniPath,L"Settings",L"AutoArm",autoArm?L"1":L"0");
 auto value=std::to_wstring(mask.load());
 writer.put(iniPath,L"Settings",L"Controls",value.c_str());
 writer.put(iniPath,L"Settings",L"ControlsSchema",L"4");
 std::wstring key;for(const char* p=profile().key;*p;++p)key+=static_cast<wchar_t>(*p);
 writer.put(iniPath,L"Settings",L"Profile",key.c_str());
 saveProfileOptions(writer);
 updateMenu();
 if(!writer.ok()){
  logf("[KozDbg] Settings save failed: file=%ls section=%ls key=%ls Windows error=%lu. Runtime settings remain applied; disk settings may be incomplete.\n",writer.path.c_str(),writer.section.c_str(),writer.key.c_str(),writer.error);
  GuiExecuteOnGuiThread(settingsSaveError);
  return false;
 }
 return true;
}
static BPXTYPE ownedType(duint address) {
 BRIDGEBP bp{};
 for(auto type:{bp_normal,bp_memory})if(DbgFunctions()->GetBridgeBp(type,address,&bp)&&
  strncmp(bp.name,"KZ_",3)==0&&strncmp(bp.commandText,"kz_hit ",7)==0)return type;
 return bp_none;
}
static bool deleteOwned(duint address){
 auto type=ownedType(address);
 if(type==bp_none)return true;
 const bool removed=cmd(std::string(type==bp_memory?"bpmc ":"bc ")+hex(address));
 return removed&&ownedType(address)==bp_none;
}
static void cleanSavedBreakpoints() {
 // Only our marked breakpoints; never erase an analyst's ordinary breakpoints.
 for(auto type:{bp_normal,bp_memory,bp_hardware,bp_dll}){
  BPMAP map{};DbgGetBpList(type,&map);
  for(int i=0;i<map.count;i++){
   if(type==bp_dll){
    if(strncmp(map.bp[i].name,"KZ_MODUNLOAD_",13)==0&&strcmp(map.bp[i].commandText,"kz_module_checkpoint")==0)cmd("bcdll \""+std::string(map.bp[i].mod)+"\"");
   }else if(type==bp_hardware){
    if(strncmp(map.bp[i].name,"KZ_FAST_",8)==0&&strcmp(map.bp[i].commandText,"kz_syscall")==0)cmd("bphc "+hex(map.bp[i].addr));
   }else if(type==bp_memory&&strncmp(map.bp[i].name,"KZ_SYS_",7)==0&&strcmp(map.bp[i].commandText,"kz_syscall")==0)cmd("bpmc "+hex(map.bp[i].addr));
   else deleteOwned(map.bp[i].addr);
  }
  if(map.bp)BridgeFree(map.bp);
 }
}
static bool isSelfHandle(duint value,bool thread) {
 if(value==(thread?duint(-2):duint(-1)))return true;
 if(!value||value>=duint(-16))return false;
 HANDLE local=nullptr;
 if(!DuplicateHandle(DbgGetProcessHandle(),(HANDLE)value,GetCurrentProcess(),&local,0,FALSE,DUPLICATE_SAME_ACCESS))return false;
 DWORD pid=thread?GetProcessIdOfThread(local):GetProcessId(local);
 CloseHandle(local);
 return pid!=0&&pid==GetProcessId(DbgGetProcessHandle());
}
static DWORD selfThreadId(duint value) {
 if(value==duint(-2))return DbgGetThreadId();
 if(!value||value>=duint(-16))return 0;
 HANDLE local=nullptr;
 if(!DuplicateHandle(DbgGetProcessHandle(),(HANDLE)value,GetCurrentProcess(),&local,0,FALSE,DUPLICATE_SAME_ACCESS))return 0;
 DWORD id=GetProcessIdOfThread(local)==GetProcessId(DbgGetProcessHandle())?GetThreadId(local):0;
 CloseHandle(local);return id;
}
static void rememberHiddenThread(duint handle) {
 if(!extendedChecks())return;
 DWORD id=selfThreadId(handle);
 if(id&&std::find(hiddenThreads.begin(),hiddenThreads.end(),id)==hiddenThreads.end())hiddenThreads.push_back(id);
}
static bool addBP(duint addr,const std::string& action) {
 if(!addr||DbgGetBpxTypeAt(addr)!=bp_none){log("Breakpoint conflict or unresolved API; existing user breakpoints were not changed.");return false;}
 // x64dbg treats an existing NAME as a match even at a different address and
 // returns success without creating another breakpoint. One name per live PC.
 const std::string address=hex(addr);
 const std::string name="KZ_"+action+"_"+address;
 const std::string command="kz_hit "+action;
 // API bindings must not remove execute permission from an entire ntdll page.
 // Stepping a blocking syscall on that page can suspend the thread it awaits.
 // Native syscall bindings are resolved past their identifying prefix below.
 if(!cmd("bp "+address+",\""+name+"\""))return false;
 BRIDGEBP actual{};
 if(!DbgFunctions()->GetBridgeBp(bp_normal,addr,&actual)||actual.addr!=addr||strcmp(actual.name,name.c_str())!=0){
  logf("[KozDbg] Breakpoint was NOT created at %p (%s). Profile will stay inactive.\n",(void*)addr,name.c_str());
  return false;
 }
 owned.push_back(addr);
 bool configured=cmd("SetBreakpointCondition "+address+",0") &&
 cmd("SetBreakpointFastResume "+address+",0") &&
 cmd("SetBreakpointCommand "+address+",\""+command+"\"") &&
 cmd("SetBreakpointCommandCondition "+address+",1") &&
 cmd("SetBreakpointSilent "+address+",1");
 if(configured){
  actual={};
  configured=DbgFunctions()->GetBridgeBp(bp_normal,addr,&actual)&&actual.addr==addr&&actual.enabled&&
   strcmp(actual.name,name.c_str())==0&&strcmp(actual.commandText,command.c_str())==0&&
   strcmp(actual.breakCondition,"0")==0&&strcmp(actual.commandCondition,"1")==0&&!actual.fastResume&&actual.silent;
 }
 if(!configured){
  logf("[KozDbg] Breakpoint setup/readback failed at %p (%s); rolling back.\n",(void*)addr,name.c_str());
  BRIDGEBP rollback{};
  if(DbgFunctions()->GetBridgeBp(bp_normal,addr,&rollback)&&strcmp(rollback.name,name.c_str())==0)cmd("bc "+address);
  owned.pop_back();
 }
 return configured;
}
struct ApiBinding {duint address;unsigned action;};
static bool addBinding(std::vector<ApiBinding>& bindings,duint address,unsigned action) {
 if(!address)return false;
 auto existing=std::find_if(bindings.begin(),bindings.end(),[&](const ApiBinding& b){return b.address==address;});
 if(existing!=bindings.end())return existing->action==action;
 bindings.push_back({address,action});return true;
}
static bool relativeAddress(duint start,size_t length,int32_t displacement,duint& result) {
 if(start>std::numeric_limits<duint>::max()-length)return false;
 duint next=start+length;
 if(displacement<0){duint magnitude=static_cast<duint>(-static_cast<int64_t>(displacement));if(next<magnitude)return false;result=next-magnitude;}
 else {if(next>std::numeric_limits<duint>::max()-static_cast<duint>(displacement))return false;result=next+static_cast<duint>(displacement);}
 return true;
}
static duint straightLineReturn(duint entry) {
 // IsDebuggerPresent is a leaf on the supported Windows path. Decode instruction
 // boundaries instead of scanning for a C3 byte inside an immediate or using an RVA.
 duint pc=entry;
 for(unsigned instructions=0;instructions<32&&pc-entry<128;instructions++){
  BASIC_INSTRUCTION_INFO info{};DbgDisasmFastAt(pc,&info);
  if(info.size<=0||info.size>15)return 0;
  unsigned char opcode=0;if(!read(pc,opcode))return 0;
  if(opcode==0xc3&&info.size==1)return pc;
  if(info.branch||info.call||opcode==0xcc||pc>std::numeric_limits<duint>::max()-info.size)return 0;
  pc+=info.size;
 }
 return 0;
}
static bool resolveBinding(std::vector<ApiBinding>& bindings,const char* symbol,unsigned action,bool required) {
 duint address=DbgValFromString(symbol);
 if(!address){if(required)logf("[KozDbg] Cannot resolve required API: %s\n",symbol);return !required;}
 // Resolve before placing INT3 bytes. Cover code thunks as well as direct calls
 // to KernelBase; a kernel32 export need not be a PE export forwarder.
 std::vector<duint> visited;
 for(unsigned hop=0;hop<16;hop++){
  if(std::find(visited.begin(),visited.end(),address)!=visited.end())return false;
  visited.push_back(address);
  logf("[KozDbg] Resolved %s%s -> %p\n",symbol,hop?" thunk":"",(void*)address);
  std::array<unsigned char,7> code{};
  if(!DbgMemRead(address,code.data(),code.size()))return false;
  duint target=0;int32_t displacement=0;size_t offset=code[0]==0x48?1:0;
  if(code[offset]==0xff&&code[offset+1]==0x25){
   memcpy(&displacement,code.data()+offset+2,sizeof(displacement));duint slot=0;
   if(!relativeAddress(address,offset+6,displacement,slot)||!read(slot,target)||!target)return false;
  } else if(code[0]==0xe9){
   memcpy(&displacement,code.data()+1,sizeof(displacement));
   if(!relativeAddress(address,5,displacement,target))return false;
  } else if(code[0]==0xeb){
   if(!relativeAddress(address,2,static_cast<int8_t>(code[1]),target))return false;
  } else {
   // Leave forwarding thunks intact. Their INT3 byte changes the protected
   // loader's behavior even though the final implementation is also covered.
   if(action!=0){
    if(strncmp(symbol,"ntdll:Nt",8)==0){
     std::array<unsigned char,24> stub{};
     if(!DbgMemRead(address,stub.data(),stub.size()))return false;
     const std::array<unsigned char,4> prefix{0x4c,0x8b,0xd1,0xb8};
     const std::array<unsigned char,16> dispatch{0xf6,0x04,0x25,0x08,0x03,0xfe,0x7f,0x01,0x75,0x03,0x0f,0x05,0xc3,0xcd,0x2e,0xc3};
     const bool prefixOk=std::equal(prefix.begin(),prefix.end(),stub.begin());
     const bool dispatchOk=std::equal(dispatch.begin(),dispatch.end(),stub.begin()+8)||
      (stub[8]==0x0f&&stub[9]==0x05&&stub[10]==0xc3);
     if(!prefixOk||!dispatchOk){logf("[KozDbg] Unsupported native syscall stub for %s; refusing a guessed API breakpoint.\n",symbol);return false;}
     // mov r10,rcx; mov eax,SSN have no stack/argument side effects.
     // Preserve those bytes for loaders which inspect the exported stub.
     address+=8;
     logf("[KozDbg] Validated post-prefix API breakpoint %s -> %p; syscall identification bytes retained.\n",symbol,(void*)address);
    }
    return addBinding(bindings,address,action);
   }
   duint returnPc=straightLineReturn(address);
   if(!returnPc){log("Cannot locate a straight-line IsDebuggerPresent RET; refusing an unverified entry-skip fallback.");return false;}
   logf("[KozDbg] IsDebuggerPresent RET resolved from instructions -> %p\n",(void*)returnPc);
   return addBinding(bindings,returnPc,action);
  }
  address=target;
 }
 log("API thunk chain is too deep; profile was not armed.");return false;
}
static bool removeBP(duint addr) {
 auto it=std::find(owned.begin(),owned.end(),addr);
 if(it!=owned.end()){if(!deleteOwned(addr))return false;owned.erase(it);}
 return true;
}
static bool disarm() {
 if(!kozBeginDisarm(armed,clearModuleHardware)){log("Disarm deferred: module hardware recovery is still pending. Current profile and armed state retained; resume or stop before reapplying.");return false;}
 if(!disarmDirect()){log("Disarm incomplete: target state or direct breakpoints could not be restored; retry records retained.");return false;}
 if(DbgIsDebugging()&&!kozRetryCleanup(owned,deleteOwned)){
  log("Disarm incomplete: owned API breakpoints remain; retry records retained.");return false;
 }
 owned.clear();pending.clear();hiddenThreads.clear();
 return true;
}
static bool armCurrentProfile() {
 if(!enabled){if(DbgIsDebugging())cleanSavedBreakpoints();log("Disabled. Owned breakpoints removed.");return true;}
 if(!DbgIsDebugging()){logf("[KozDbg] %s selected; waiting for a new debug session.\n",profile().version);return true;}
 if(!installDebugEventTail()){log("Cannot install the debugger event-tail checkpoint; profile was not armed.");return false;}
 // Architecture check only: no filename, hash, image-base or RVA dependency.
 IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS64 nt{};duint imageBase=M::GetMainModuleBase();
 if(!imageBase||!read(imageBase,dos)||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0||
    !read(imageBase+(duint)dos.e_lfanew,nt)||nt.Signature!=IMAGE_NT_SIGNATURE||
    nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64||nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC){
  log("This build supports native x64 targets only.");return false;
 }
 cleanSavedBreakpoints();
 const char* names[]={"kernel32:IsDebuggerPresent","kernel32:CheckRemoteDebuggerPresent","ntdll:NtQueryInformationProcess","ntdll:NtSetInformationThread","ntdll:NtQuerySystemInformation","ntdll:NtClose"};
 std::vector<ApiBinding> bindings;
 bool ok=true;
 for(unsigned i=0;i<6&&ok;i++){
  bool needed=i<4?on(i):(i==4?(on(4)||on(5)):on(6));
  if(advanced()&&i==2)needed=on(1)||on(2);
  if(needed)ok=resolveBinding(bindings,names[i],i,true);
 }
 if(ok&&on(0))ok=resolveBinding(bindings,"kernelbase:IsDebuggerPresent",0,false);
 if(ok&&on(1))ok=resolveBinding(bindings,"kernelbase:CheckRemoteDebuggerPresent",1,false);
 for(const auto& binding:bindings){if(!ok)break;ok=addBP(binding.address,std::to_string(binding.action));}
 if(ok){
  try {ok=advanced()?setupDirect():setupLegacyContext();}
  catch(const std::bad_alloc&){log("Arming failed: insufficient memory while preparing scan/check state.");ok=false;}
 }
 if(!ok){if(disarm())log("Arming failed; all breakpoints created by this attempt were removed.");else log("Arming failed and cleanup remains pending; stop the session before trying again.");return false;}
 armed=true;
 logf("[KozDbg] Verified %u API breakpoints by address, name and command.\n",static_cast<unsigned>(owned.size()));
 logf("[KozDbg] %s profile armed. Addresses resolved in this process; no sample-specific offsets. F9 to continue.\n",profile().version);return true;
}
static bool apply(int,char**) {
 if(DbgIsDebugging()&&DbgIsRunning()){log("Pause the target before applying a profile.");return false;}
 return disarm()&&armCurrentProfile();
}
static bool configureProfile(unsigned index,unsigned options,bool enable,bool automatic) {
 if(index>=profiles.size()||(DbgIsDebugging()&&DbgIsRunning())){
  log("Pause the target before applying changes.");return false;
 }
 return kozChangeConfiguration(disarm,[&]{
  selectedProfile=index;mask=options&8191;enabled=enable;autoArm=automatic;
 },armCurrentProfile,saveSettings);
}
static bool configureCommand(int argc,char** argv) {
 if(argc!=5)return false;
 unsigned values[4]{};
 for(unsigned i=0;i<4;i++){
  const char* p=argv[i+1];if(!*p)return false;
  for(;*p;++p){if(*p<'0'||*p>'9'||values[i]>8191)return false;values[i]=values[i]*10+static_cast<unsigned>(*p-'0');}
 }
 if(values[0]>=profiles.size()||values[1]>8191||values[2]>1||values[3]>1)return false;
 return configureProfile(values[0],values[1],values[2]!=0,values[3]!=0);
}
static bool filterModules(const Pending& p) {
 if((int32_t)R::GetEAX()<0)return true;
 uint32_t countModules=0;
 if(!read(p.buffer,countModules)||p.size<8||countModules>(p.size-8)/0x128||countModules>65536)return false;
 std::vector<unsigned char> data((size_t)countModules*0x128);
 if(!data.empty()&&!DbgMemRead(p.buffer+8,data.data(),data.size()))return false;
 uint32_t kept=0,removed=0;
 for(uint32_t i=0;i<countModules;i++){
  auto record=data.data()+i*0x128;uint16_t offset;memcpy(&offset,record+0x26,2);
  if(offset>=256)return false;
  const char* name=(char*)record+0x28+offset;size_t room=256-offset;
  if(!memchr(name,0,room))return false;
  bool blocked=false;
  for(auto s:{"sice.sys","siwvid.sys","ntice.sys","iceext.sys","syser.sys"})if(_stricmp(name,s)==0)blocked=true;
  if(blocked){++removed;continue;}
  if(kept!=i)memmove(data.data()+kept*0x128,record,0x128);
  ++kept;
 }
 if(removed){
  std::fill(data.begin()+kept*0x128,data.end(),static_cast<unsigned char>(0));
  if(!DbgMemWrite(p.buffer+8,data.data(),data.size())||!write(p.buffer,kept))return false;
 }
 ++hits[5];infof("Module list filtered","[KozDbg] Module list: %u records, %u matching names removed.\n",countModules,removed);return true;
}
static bool watchReturn(duint address,ReturnKind kind,duint buffer,duint size,duint sp,duint stackDelta=8) {
 // Distinguish concurrent callers and recursive calls, even with the same return PC.
 if(pending.size()>=4096)return false;
 DWORD thread=DbgGetThreadId();
 if(std::any_of(pending.begin(),pending.end(),[&](const Pending& p){
  return p.address==address&&p.thread==thread&&p.stack==sp+stackDelta&&p.kind==kind&&p.buffer==buffer;
 }))return true;
 bool already=std::any_of(pending.begin(),pending.end(),[&](const Pending& p){return p.address==address;});
 if(!already&&!addBP(address,"return"))return false;
 pending.push_back({address,buffer,size,sp+stackDelta,thread,kind});return true;
}
static bool processReturn(const Pending& p) {
 if(p.kind==ReturnKind::Attach)return !R::GetEAX()||restoreAttach();
 if(p.kind==ReturnKind::Modules)return filterModules(p);
 if(p.kind==ReturnKind::Remote){
  if(!R::GetEAX())return true;
  uint32_t value=0;if(!write(p.buffer,value))return false;
  count(1,"Successful remote debugger query: output -> FALSE");return true;
 }
 if((int32_t)R::GetEAX()<0)return true;
 if(p.kind==ReturnKind::HiddenThread){
  if(std::find(hiddenThreads.begin(),hiddenThreads.end(),static_cast<DWORD>(p.size))==hiddenThreads.end())return true;
  unsigned char before=0;
  if(!read(p.buffer,before)||!write(p.buffer,static_cast<unsigned char>(1)))return false;
  ++hits[3];infof("ThreadHideFromDebugger query adjusted","[KozDbg] Successful ThreadHideFromDebugger query for tid=%X: %u -> 1; real status and ReturnLength preserved\n",static_cast<DWORD>(p.size),before);return true;
 }
 uint16_t value=0x100;if(!write(p.buffer,value))return false;
 count(4,"Successful kernel debugger query: bytes -> 00 01");return true;
}
static bool hit(int argc,char** argv) {
 if(argc<2||!armed)return true;
 bool ok=true;duint ip=R::GetRIP(),sp=R::GetRSP(),ra=0;
 if(strcmp(argv[1],"return")==0){
  auto it=std::find_if(pending.begin(),pending.end(),[&](const Pending& p){return p.address==ip&&p.thread==DbgGetThreadId()&&p.stack==sp;});
  if(it!=pending.end()){
   auto p=*it;pending.erase(it);ok=processReturn(p);
   if(std::none_of(pending.begin(),pending.end(),[&](const Pending& other){return other.address==ip;}))ok=removeBP(ip)&&ok;
  }
 } else if(read(sp,ra)) {
  int n=atoi(argv[1]);
  if(n<0||n>=static_cast<int>(apiSeen.size()))return false;
  if(apiSeen[n]++==0){
   char caller[MAX_MODULE_SIZE]{};
   if(!M::NameFromAddr(ra,caller))strcpy_s(caller,"unmapped/private");
   logf("[KozDbg] API %d hit=%u tid=%X pc=%p caller=%s:%p rsp=%p rcx=%p rdx=%p\n",
    n,apiSeen[n].load(),DbgGetThreadId(),(void*)ip,caller,(void*)ra,(void*)sp,(void*)R::GetRCX(),(void*)R::GetRDX());
  }
  if(n<4&&(on(n)||(advanced()&&n==2&&on(1)))){
   switch(n){
    case 0:{
     // This binding is at the decoded RET, after the real PEB read. Preserve RIP
     // and RSP so the CPU performs the normal return, as in the recorded manual test.
     unsigned char opcode=0;duint before=R::GetRAX();
     ok=read(ip,opcode)&&opcode==0xc3&&R::SetRAX(0)&&R::GetRAX()==0&&R::GetRIP()==ip&&R::GetRSP()==sp;
     if(ok){++hits[0];infof("IsDebuggerPresent return adjusted","[KozDbg] IsDebuggerPresent RET: RAX %p -> 0 (readback verified), caller=%p; native RET will execute.\n",(void*)before,(void*)ra);}
     break;
    }
    case 1:if(isSelfHandle(R::GetRCX(),false)&&R::GetRDX())ok=watchReturn(ra,ReturnKind::Remote,R::GetRDX(),4,sp);break;
    case 2:if(advanced()){
     duint returnLength=0,statusValue=0;
     if(read(sp+0x28,returnLength)&&emulateQuery(R::GetRCX(),R::GetEDX(),R::GetR8(),R::GetR9(),returnLength,statusValue))ok=ret(ra,statusValue);
    }else if(R::GetEDX()==0x1e&&R::GetR9()==8&&R::GetR8()&&
      (R::GetR8()&7)==0&&isSelfHandle(R::GetRCX(),false)){
     // No successful query is executed: no real debug-object handle is leaked.
     ok=ret(ra,0xc0000353);if(ok)count(2,"Self debug object query -> STATUS_PORT_NOT_SET");
    }break;
    case 3:if(R::GetEDX()==0x11&&R::GetR8()==0&&R::GetR9()==0&&isSelfHandle(R::GetRCX(),true)){
     rememberHiddenThread(R::GetRCX());
     ok=ret(ra,0);if(ok)count(3,"ThreadHideFromDebugger suppressed");
    }break;
   }
  }
  if(n==4){
   if(on(4)&&R::GetECX()==0x23&&R::GetR8()>=2&&R::GetRDX()){
    ok=watchReturn(ra,ReturnKind::Kernel,R::GetRDX(),R::GetR8(),sp);
   } else if(on(5)&&R::GetECX()==0xb&&R::GetR8()>=8&&R::GetRDX()){
    ok=watchReturn(ra,ReturnKind::Modules,R::GetRDX(),R::GetR8(),sp);
   }
  }
  // NtClose is called inside CloseHandle, so its immediate caller is KernelBase.
  // DEADC0DE is the researched invalid-handle input, not a code address.
  if(n==5&&on(6)&&R::GetRCX()==0xdeadc0de){ok=prepareTfWindow(ra)&&ret(ra,0xc0000008);if(ok)count(6,"Invalid NtClose -> STATUS_INVALID_HANDLE without debugger exception");}
  if(n>=6&&(advanced()||(on(9)&&n>=7&&n<=9)))ok=hitDirect(n,ip,sp,ra);
 }
 if(!ok){log("An operation failed. Pausing for inspection; no automatic resume.");cmd("mov $breakpointcondition,1");}
 return ok;
}
#include "direct_syscalls.inl"
#include "module_hardware.inl"
#include "debug_event_tail.inl"
static bool status(int,char**) {
 logf("[KozDbg] Profile: %s | armed: %s | auto-arm: %s\n",enabled?profile().version:"Disabled",armed?"yes":"no",autoArm?"yes":"no");
 const char* labels[]={"PEB/API state","Remote/debug port","Debug object","Thread hide","Kernel debugger","Module list","Invalid handle","TF delivery","Keep callback","Saved DR context","Keep remote breakin","Protect TitanHide","Decoder acceleration"};
 for(unsigned i=0;i<controlCount;i++)logf("  %-20s %s | %u\n",labels[i],(i>=8&&i!=9&&!advanced())||(i==11&&!extendedChecks())?"n/a":(on(i)?"on ":"off"),hits[i].load());
 logf("[KozDbg] Suspended TF guard windows: %u\n",tfGuardStatus.load());
 for(const auto& hardware:hardwareStatus.snapshot())logf("[KozDbg] Decoder hardware site: %p | slot: %u\n",(void*)hardware.address,hardware.slot);
 logf("[KozDbg] Module hardware: %u loads, %u unloads, %u conflicts | pending=%u\n",moduleHardwareLoads.load(),moduleHardwareUnloads.load(),moduleHardwareConflicts.load(),moduleHardwarePhaseStatus.load());
 printInfoCounts();
 for(unsigned i=0;i<apiSeen.size();i++){const auto visits=apiSeen[i].load();if(visits)logf("  API %u visits: %u\n",i,visits);}
 return true;
}
static bool select(int argc,char** argv) {
 if(DbgIsDebugging()&&DbgIsRunning()){log("Pause before changing the selected profile.");return false;}
 if(argc!=2){log("Usage: kz_profile <INI section name> | off");return false;}
 if(strcmp(argv[1],"off")==0)return configureProfile(selectedProfile,mask,false,autoArm);
 for(unsigned i=0;i<profiles.size();i++)if(strcmp(argv[1],profiles[i].key)==0||strcmp(argv[1],profiles[i].version)==0){
  return configureProfile(i,readProfileOptions(i),true,autoArm);
 }
 log("Usage: kz_profile <INI section name> | off");return false;
}
static void enableAdvancedControls(HWND wnd){
 const auto choice=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);
 const bool valid=choice>=0&&choice<static_cast<LRESULT>(profiles.size());
 const bool available=valid&&profiles[static_cast<size_t>(choice)].engine!=Engine::Api;
 for(unsigned i=8;i<11;i++)EnableWindow(GetDlgItem(wnd,120+i),available||(i==9&&valid));
 EnableWindow(GetDlgItem(wnd,131),valid&&available&&profiles[static_cast<size_t>(choice)].extended);
 EnableWindow(GetDlgItem(wnd,132),available);
}
static void createSettingsTooltips(HWND wnd){
 static constexpr std::array<const wchar_t*,controlCount> help{{
  L"Hides the debugger flag reported through the PEB and IsDebuggerPresent.",
  L"Makes supported remote-debugger and debug-port queries report no debugger.",
  L"Handles supported debug-object queries used to detect an attached debugger.",
  L"Prevents the program from hiding its threads from the debugger.",
  L"Makes supported kernel-debugger queries report no kernel debugger.",
  L"Filters the five driver names identified in our research from supported module queries. Does not unload drivers.",
  L"Handles the invalid-handle checks identified in the selected profile.",
  L"Allows the program's expected trap-flag exception to reach its handler during the supported check.",
  L"Prevents the program from clearing the instrumentation callback through the supported call. Available in later profiles.",
  L"Hides saved DR0-DR3 from the supported exception filter, then restores them. Your hardware breakpoints remain available.",
  L"Restores the DbgUiRemoteBreakin entry after the supported self-process write. This is not a guarantee for every late-attach path.",
  L"Blocks the exact TitanHide device open used by 3.9.4 and 3.10.1. Unrelated devices are unaffected; no driver is installed.",
  L"Speeds up decoder-page handling using free hardware breakpoint slots for every candidate on one decoder page. Does not replace your existing breakpoints."
 }};
 settingsTooltips=CreateWindowExW(WS_EX_TOPMOST|WS_EX_NOACTIVATE,TOOLTIPS_CLASSW,nullptr,
  WS_POPUP|TTS_ALWAYSTIP|TTS_NOPREFIX,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,
  wnd,nullptr,instance,nullptr);
 if(!settingsTooltips)return;
 SendMessageW(settingsTooltips,WM_SETFONT,SendMessageW(wnd,WM_GETFONT,0,0),FALSE);
 SendMessageW(settingsTooltips,TTM_SETMAXTIPWIDTH,0,MulDiv(340,GetDpiForWindow(wnd),96));
 SendMessageW(settingsTooltips,TTM_SETDELAYTIME,TTDT_INITIAL,350);
 SendMessageW(settingsTooltips,TTM_SETDELAYTIME,TTDT_AUTOPOP,20000);
 const auto add=[&](int id,const wchar_t* text){
  const HWND control=GetDlgItem(wnd,id);if(!control)return;
  TOOLINFOW tool{};tool.cbSize=sizeof(tool);tool.uFlags=TTF_IDISHWND|TTF_SUBCLASS;
  tool.hwnd=wnd;tool.uId=reinterpret_cast<UINT_PTR>(control);tool.lpszText=const_cast<wchar_t*>(text);
  SendMessageW(settingsTooltips,TTM_ADDTOOLW,0,reinterpret_cast<LPARAM>(&tool));
 };
 add(110,L"Select the VMProtect version to use. Unavailable options are greyed out for that profile.");
 const wchar_t* autoHelp=L"Automatically applies the selected profile when a new debugging session starts.";
 add(111,autoHelp);add(200,autoHelp);
 for(unsigned i=0;i<controlCount;i++){add(120+i,help[i]);add(201+i,help[i]);}
}
static INT_PTR CALLBACK dialogProc(HWND wnd,UINT msg,WPARAM wp,LPARAM) {
 if(msg==WM_INITDIALOG){
  settingsWindow=wnd;
  SendMessageW(wnd,WM_SETICON,ICON_SMALL,(LPARAM)LoadIconW(instance,MAKEINTRESOURCEW(102)));
  SendMessageW(wnd,WM_SETICON,ICON_BIG,(LPARAM)LoadIconW(instance,MAKEINTRESOURCEW(102)));
  for(const auto& p:profiles)SendDlgItemMessageW(wnd,110,CB_ADDSTRING,0,(LPARAM)p.label);
  SendDlgItemMessageW(wnd,110,CB_ADDSTRING,0,(LPARAM)L"Disabled");
  SendDlgItemMessageW(wnd,110,CB_SETCURSEL,enabled?selectedProfile.load():profiles.size(),0);
  CheckDlgButton(wnd,111,autoArm?BST_CHECKED:BST_UNCHECKED);
  for(unsigned i=0;i<controlCount;i++)CheckDlgButton(wnd,120+i,on(i)?BST_CHECKED:BST_UNCHECKED);
  enableAdvancedControls(wnd);
  createSettingsTooltips(wnd);return TRUE;
 }
 if(msg==WM_COMMAND){
  if(LOWORD(wp)==110&&HIWORD(wp)==CBN_SELCHANGE){
   const auto choice=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);
   if(choice>=0&&choice<static_cast<LRESULT>(profiles.size())){
    const unsigned options=readProfileOptions(static_cast<unsigned>(choice));
    for(unsigned i=0;i<controlCount;i++)CheckDlgButton(wnd,120+i,(options&(1u<<i))?BST_CHECKED:BST_UNCHECKED);
   }
   enableAdvancedControls(wnd);return TRUE;
  }
  if(LOWORD(wp)==150){MessageBoxW(wnd,L"KozDbg\n\nCreator: Ivan Kozlovsky\ncontact@ivankozlovsky.com\nivankozlovsky.com\n\nOpen source - MIT License\nProfiles: editable INI presets\nImplementation: C++ source",L"About KozDbg",MB_OK|MB_ICONINFORMATION);return TRUE;}
  if(LOWORD(wp)==151){ShellExecuteW(wnd,L"open",L"notepad.exe",(L"\""+profilesPath+L"\"").c_str(),nullptr,SW_SHOWNORMAL);return TRUE;}
  if(LOWORD(wp)==IDCANCEL){EndDialog(wnd,0);return TRUE;}
  if(LOWORD(wp)==IDOK){
   if(DbgIsDebugging()&&DbgIsRunning()){MessageBoxW(wnd,L"Pause the target before applying changes.",L"KozDbg",MB_OK|MB_ICONINFORMATION);return TRUE;}
   const auto choice=SendDlgItemMessageW(wnd,110,CB_GETCURSEL,0,0);
   if(choice<0||choice>static_cast<LRESULT>(profiles.size()))return TRUE;
   const bool requestedEnabled=choice<static_cast<LRESULT>(profiles.size());
   const unsigned requestedProfile=requestedEnabled?static_cast<unsigned>(choice):selectedProfile.load();
   const bool requestedAuto=IsDlgButtonChecked(wnd,111)==BST_CHECKED;unsigned m=0;
   for(unsigned i=0;i<controlCount;i++)if(IsDlgButtonChecked(wnd,120+i)==BST_CHECKED)m|=1u<<i;
   const std::string request="kz_config "+std::to_string(requestedProfile)+","+std::to_string(m)+","+
    (requestedEnabled?"1":"0")+","+(requestedAuto?"1":"0");
   if(!DbgCmdExec(request.c_str())){MessageBoxW(wnd,L"Could not queue settings. No changes were applied.",L"KozDbg",MB_OK|MB_ICONERROR);return TRUE;}
   EndDialog(wnd,1);return TRUE;
  }
 }
 if(msg==WM_DESTROY){if(settingsTooltips)DestroyWindow(settingsTooltips);settingsTooltips=nullptr;settingsWindow=nullptr;}
 return FALSE;
}
static void showUI(){if(settingsWindow){SetForegroundWindow(settingsWindow);return;}DialogBoxParamW(instance,MAKEINTRESOURCEW(101),owner,dialogProc,0);}
static bool settings(int,char**){GuiExecuteOnGuiThread(showUI);return true;}
static void callback(CBTYPE type,void* info) {
 moduleHardwareEvent(type,info);
 if(type==CB_MENUENTRY){
  int id=((PLUG_CB_MENUENTRY*)info)->hEntry;
  for(const auto& p:profiles)if(id==p.menuId)DbgCmdExec((std::string("kz_profile ")+p.key).c_str());
  if(id==2)DbgCmdExec("kz_profile off");
  if(id==3)settings(0,nullptr);
  if(id==4)DbgCmdExec("kz_apply");
  if(id==5){autoArm=!autoArm;saveSettings();}
  if(id==6){DbgCmdExec("kz_status");GuiFlushLog();}
 } else if(type==CB_SYSTEMBREAKPOINT){if(enabled&&autoArm)DbgCmdExec("kz_apply");}
 else if(type==CB_INITDEBUG){armed=false;owned.clear();pending.clear();for(auto& n:hits)n=0;for(auto& n:apiSeen)n=0;resetInfoCounts();moduleHardwareLoads=0;moduleHardwareUnloads=0;moduleHardwareConflicts=0;}
 else if(type==CB_EXITPROCESS){
  log("Process exit: recorded intervention totals follow (not proof of reaching original entry).");status(0,nullptr);
  logf("[KozDbg] Pending API returns at exit: %u\n",static_cast<unsigned>(pending.size()));
 }
 else if(type==CB_STOPPINGDEBUG||type==CB_DETACH){disarm();}
 else if(type==CB_STOPDEBUG){armed=false;owned.clear();pending.clear();}
 else if(type==CB_EXITTHREAD){
  auto id=((PLUG_CB_EXITTHREAD*)info)->dwThreadId;
  dropSavedContexts(id);
  if(!restoreTfGuards(id,0))log("Failed to restore syscall guards after thread exit; restart the session.");
  hiddenThreads.erase(std::remove(hiddenThreads.begin(),hiddenThreads.end(),id),hiddenThreads.end());
  std::vector<duint> removed;
  for(const auto& p:pending)if(p.thread==id)removed.push_back(p.address);
  pending.erase(std::remove_if(pending.begin(),pending.end(),[&](const Pending& p){return p.thread==id;}),pending.end());
  for(auto addr:removed)if(std::none_of(pending.begin(),pending.end(),[&](const Pending& p){return p.address==addr;}))removeBP(addr);
 }
 else if(type==CB_EXCEPTION&&armed&&on(7)){
  auto e=((PLUG_CB_EXCEPTION*)info)->Exception;
  if(e->dwFirstChance&&e->ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP){
   duint ip=(duint)e->ExceptionRecord.ExceptionAddress;
   std::array<unsigned char,4> bytes{};duint poppedFlags=0;
   // Recognize the program's POPFQ / RDTSC / NOP TF probe in live memory.
   // Ordinary steps, hardware-breakpoint hits and other exception sites are left alone.
   if(ip>=3&&R::GetRSP()>=8&&DbgMemRead(ip-3,bytes.data(),bytes.size())&&
      bytes==std::array<unsigned char,4>{0x9d,0x0f,0x31,0x90}&&
      read(R::GetRSP()-8,poppedFlags)&&(poppedFlags&0x100)&&!(R::GetDR6()&0xf)){
    count(7,"Delivering the runtime POPFQ / RDTSC / NOP exception to the program");
    DbgCmdExec("erun");
   }
  }
 }
}
extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init){
 pluginHandle=init->pluginHandle;init->sdkVersion=PLUG_SDKVERSION;init->pluginVersion=101;
 strcpy_s(init->pluginName,"KozDbg");
 wchar_t file[MAX_PATH];GetModuleFileNameW(instance,file,MAX_PATH);iniPath=file;iniPath+=L".ini";logPath=file;logPath+=L".log";
 enabled=GetPrivateProfileIntW(L"Settings",L"Enabled",1,iniPath.c_str())!=0;
 autoArm=GetPrivateProfileIntW(L"Settings",L"AutoArm",1,iniPath.c_str())!=0;
 mask=GetPrivateProfileIntW(L"Settings",L"Controls",8191,iniPath.c_str())&8191;
 if(GetPrivateProfileIntW(L"Settings",L"ControlsSchema",1,iniPath.c_str())<2)mask=mask.load()|0x700;
 if(GetPrivateProfileIntW(L"Settings",L"ControlsSchema",1,iniPath.c_str())<3)mask=mask.load()|0x800;
 if(GetPrivateProfileIntW(L"Settings",L"ControlsSchema",1,iniPath.c_str())<4)mask=mask.load()|0x1000;
 profilesPath=iniPath+L".profiles.ini";
 loadProfiles();
 wchar_t savedProfile[128]{};GetPrivateProfileStringW(L"Settings",L"Profile",L"331",savedProfile,128,iniPath.c_str());
 for(unsigned i=0;i<profiles.size();i++)if(widen(profiles[i].key)==savedProfile)selectedProfile=i;
 mask=readProfileOptions(selectedProfile);
 _plugin_registercommand(pluginHandle,"kz_apply",apply,false);
 _plugin_registercommand(pluginHandle,"kz_config",configureCommand,false);
 _plugin_registercommand(pluginHandle,"kz_hit",hit,true);
 _plugin_registercommand(pluginHandle,"kz_syscall",syscallHit,true);
 _plugin_registercommand(pluginHandle,"kz_profile",select,false);
 _plugin_registercommand(pluginHandle,"kz_settings",settings,false);
 _plugin_registercommand(pluginHandle,"kz_status",status,false);
 for(auto t:{CB_MENUENTRY,CB_SYSTEMBREAKPOINT,CB_INITDEBUG,CB_STOPPINGDEBUG,CB_STOPDEBUG,CB_DETACH,CB_EXITPROCESS,CB_EXITTHREAD,CB_EXCEPTION,CB_DEBUGEVENT,CB_LOADDLL,CB_UNLOADDLL,CB_BREAKPOINT})_plugin_registercallback(pluginHandle,t,callback);
 log("Loaded v1.0.1 - 3.3.1 / 3.4.0 / 3.5.0 / 3.6 / 3.8.0 / 3.9.4 / 3.10.1 x64 profiles. Settings are in Plugins > KozDbg.");return true;
}
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup){
 owner=setup->hwndDlg;
 const HRSRC iconResource=FindResourceW(instance,MAKEINTRESOURCEW(103),RT_RCDATA);
 if(iconResource){
  const HGLOBAL iconData=LoadResource(instance,iconResource);
  ICONDATA icon{};icon.data=iconData?LockResource(iconData):nullptr;icon.size=SizeofResource(instance,iconResource);
  if(icon.data&&icon.size)_plugin_menuseticon(setup->hMenu,&icon);
 }
 for(const auto& p:profiles)_plugin_menuaddentry(setup->hMenu,p.menuId,p.menu);
 _plugin_menuaddentry(setup->hMenu,2,"Disabled");
 _plugin_menuaddseparator(setup->hMenu);
 _plugin_menuaddentry(setup->hMenu,3,"Settings...");
 _plugin_menuaddentry(setup->hMenu,4,"Apply to paused session");
 _plugin_menuaddentry(setup->hMenu,5,"Auto-arm on start");
 _plugin_menuaddentry(setup->hMenu,6,"Session log");setupDone=true;updateMenu();
}
extern "C" __declspec(dllexport) bool plugstop(){
 if(settingsWindow){log("Close KozDbg settings before unloading the plugin.");return false;}
 if(moduleHardwarePauseActive){log("Cannot free KozDbg while its callback is paused. x64dbg may still detach plugin commands/callbacks; stop the session and restart x64dbg.");return false;}
 if(DbgIsDebugging()&&DbgIsRunning()){log("Pause or stop the target before unloading KozDbg.");return false;}
 if(!disarm()){log("Cannot free KozDbg: hardware recovery is pending. x64dbg may still detach plugin commands/callbacks; stop the session and restart x64dbg.");return false;}
 if(!removeDebugEventTail())return false;
 for(auto n:{"kz_apply","kz_config","kz_hit","kz_syscall","kz_profile","kz_settings","kz_status"})_plugin_unregistercommand(pluginHandle,n);
 return true;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID){if(reason==DLL_PROCESS_ATTACH){instance=module;DisableThreadLibraryCalls(module);}return TRUE;}
