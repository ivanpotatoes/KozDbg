// Shared native x64 syscall engine. All sites and service numbers are live.
static std::vector<duint> syscallSites;
static std::vector<duint> guardedSites;
struct HardwareSyscall {duint address=0;unsigned slot=4;};
static std::vector<HardwareSyscall> hardwareSyscalls;
static bool ownedHardware(duint address) {
 BRIDGEBP bp{};return address&&DbgFunctions()->GetBridgeBp(bp_hardware,address,&bp)&&
  strncmp(bp.name,"KZ_FAST_",8)==0&&strcmp(bp.commandText,"kz_syscall")==0;
}
static bool rangeDecoderPage(duint page,size_t length) {
 std::vector<unsigned char> bytes(length+102);
 if(!DbgMemRead(page,bytes.data(),bytes.size())){
  bytes.resize(length);if(!DbgMemRead(page,bytes.data(),bytes.size()))return false;
 }
 // Range normalization compares a 32-bit register with 1<<24, then reads a
 // byte and shifts the range by eight. Register allocation is not fixed.
 for(size_t i=0;i+6<length;i++){
  if(bytes[i]!=0x81||bytes[i+1]<0xf8||bytes[i+2]!=0||bytes[i+3]!=0||bytes[i+4]!=0||bytes[i+5]!=1)continue;
  bool byteLoad=false,shiftEight=false,conditional=false;
  const size_t end=std::min(bytes.size(),i+102);
  for(size_t j=i+6;j+2<end;j++){
   if(bytes[j]==0x0f&&bytes[j+1]==0xb6)byteLoad=true;
   if(bytes[j]==0xc1&&(bytes[j+1]&0xf8)==0xe0&&bytes[j+2]==8)shiftEight=true;
   if((bytes[j]>=0x70&&bytes[j]<=0x7f)||(bytes[j]==0x0f&&bytes[j+1]>=0x80&&bytes[j+1]<=0x8f))conditional=true;
  }
  if(byteLoad&&shiftEight&&conditional)return true;
 }
 return false;
}
static bool addHardwareSyscall(duint address) {
 BPMAP map{};DbgGetBpList(bp_hardware,&map);
 unsigned occupied=0;bool unmanaged=false;
 for(int i=0;i<map.count;i++)if(map.bp[i].slot<4)occupied|=1u<<map.bp[i].slot;
 if(map.bp)BridgeFree(map.bp);
 const std::array<duint,4> before{R::GetDR0(),R::GetDR1(),R::GetDR2(),R::GetDR3()};
 const duint dr7=R::GetDR7();
 for(unsigned i=0;i<4;i++)if((before[i]||((dr7>>(i*2))&3))&&!(occupied&(1u<<i)))unmanaged=true;
 if(occupied==15||unmanaged){log("Decoder acceleration unavailable: no safely available hardware slot; retaining memory guards.");return false;}
 BRIDGEBP bp{};if(DbgFunctions()->GetBridgeBp(bp_hardware,address,&bp))return false;
 const auto a=hex(address);
 if(!cmd("bph "+a+",x,1"))return false;
 bool ok=cmd("SetHardwareBreakpointName "+a+",KZ_FAST_"+a)&&
  cmd("SetHardwareBreakpointCondition "+a+",0")&&cmd("SetHardwareBreakpointFastResume "+a+",0")&&
  cmd("SetHardwareBreakpointCommand "+a+",kz_syscall")&&cmd("SetHardwareBreakpointCommandCondition "+a+",1")&&
  cmd("SetHardwareBreakpointSilent "+a+",1")&&DbgFunctions()->GetBridgeBp(bp_hardware,address,&bp)&&
  bp.slot<4&&!(occupied&(1u<<bp.slot))&&bp.enabled&&!bp.fastResume&&bp.silent&&ownedHardware(address)&&
  strcmp(bp.breakCondition,"0")==0&&strcmp(bp.commandCondition,"1")==0;
 if(!ok){cmd("bphc "+a);log("Decoder hardware setup failed; retaining memory guards.");return false;}
 hardwareSyscalls.push_back({address,bp.slot});
 ++hits[12];logf("[KozDbg] Decoder-page syscall %p uses free DR%u; all other sites retain memory guards.\n",(void*)address,bp.slot);
 return true;
}
struct TfGuardWindow {DWORD thread;duint exceptionAddress;std::vector<duint> sites;};
static std::vector<TfGuardWindow> tfGuardWindows;
static duint pebByte=0,remoteBreakin=0;
static unsigned char savedPebByte=0;
static DWORD advancedPid=0;
static std::array<unsigned char,32> breakinBytes{};
static unsigned queryProcessSSN=0,setThreadSSN=0,setProcessSSN=0;
static unsigned queryThreadSSN=0,querySystemSSN=0,openFileSSN=0;
struct SavedDebugContext {DWORD thread;duint address,exceptionRecord,exceptionIP;std::array<duint,4> dr;};
static std::vector<SavedDebugContext> savedContexts;
static void dropSavedContexts(DWORD thread){
 savedContexts.erase(std::remove_if(savedContexts.begin(),savedContexts.end(),[&](const SavedDebugContext& c){return c.thread==thread;}),savedContexts.end());
}

static bool writable(duint address,size_t size) {
 if(!address||address>std::numeric_limits<duint>::max()-size)return false;
 duint end=address+size;
 while(address<end){
  MEMORY_BASIC_INFORMATION m{};
  if(!VirtualQueryEx(DbgGetProcessHandle(),(LPCVOID)address,&m,sizeof(m))||m.State!=MEM_COMMIT||(m.Protect&PAGE_GUARD))return false;
  DWORD protection=m.Protect&0xff;
  if(protection!=PAGE_READWRITE&&protection!=PAGE_WRITECOPY&&protection!=PAGE_EXECUTE_READWRITE&&protection!=PAGE_EXECUTE_WRITECOPY)return false;
  duint next=(duint)m.BaseAddress+m.RegionSize;if(next<=address)return false;address=next;
 }
 return true;
}
static bool syscallNumber(const char* name,unsigned& number) {
 duint start=DbgValFromString(name);if(!start)return false;
 bool found=false;
 for(duint pc=start;pc<start+64;){
  BASIC_INSTRUCTION_INFO info{};DbgDisasmFastAt(pc,&info);if(info.size<=0||info.size>15)return false;
  std::array<unsigned char,5> bytes{};if(!DbgMemRead(pc,bytes.data(),bytes.size()))return false;
  if(bytes[0]==0xb8&&info.size==5){memcpy(&number,bytes.data()+1,4);found=true;}
  if(bytes[0]==0x0f&&bytes[1]==0x05){if(found)logf("[KozDbg] Live SSN %s = %X\n",name,number);return found;}
  if(bytes[0]==0xc3)return false;
  pc+=info.size;
 }
 return false;
}
static bool ownedGuard(duint address) {
 BRIDGEBP bp{};return DbgFunctions()->GetBridgeBp(bp_memory,address,&bp)&&strncmp(bp.name,"KZ_SYS_",7)==0&&strcmp(bp.commandText,"kz_syscall")==0;
}
static bool addGuard(duint address) {
 BRIDGEBP old{};if(DbgFunctions()->GetBridgeBp(bp_memory,address,&old)){log("Existing memory breakpoint conflicts with a syscall site.");return false;}
 std::string a=hex(address);
 if(!cmd("bpmrange "+a+",2,x"))return false;
 guardedSites.push_back(address);
 if(!cmd("SetMemoryBreakpointName "+a+",KZ_SYS_"+a)||
    !cmd("SetMemoryBreakpointCondition "+a+",0")||
    !cmd("SetMemoryBreakpointFastResume "+a+",0")||
    !cmd("SetMemoryBreakpointCommand "+a+",kz_syscall")||
    !cmd("SetMemoryBreakpointCommandCondition "+a+",1")||
    !cmd("SetMemoryBreakpointSilent "+a+",1")){cmd("bpmc "+a);guardedSites.pop_back();return false;}
 BRIDGEBP bp{};
 bool verified=DbgFunctions()->GetBridgeBp(bp_memory,address,&bp)&&bp.enabled&&!bp.fastResume&&bp.silent&&ownedGuard(address)&&
  strcmp(bp.breakCondition,"0")==0&&strcmp(bp.commandCondition,"1")==0;
 if(!verified){cmd("bpmc "+a);guardedSites.pop_back();}
 return verified;
}
static bool preserveHardwareContext() {
 if(hardwareSyscalls.empty())return true;
 const duint address=R::GetRCX();CONTEXT context{};
 if(!read(address,context)||(context.ContextFlags&CONTEXT_DEBUG_REGISTERS)!=CONTEXT_DEBUG_REGISTERS)return true;
 for(size_t i=0;i<hardwareSyscalls.size();){
  const auto hardware=hardwareSyscalls[i];
  if(!ownedHardware(hardware.address)){log("Owned decoder breakpoint was changed or removed; pausing to avoid losing coverage.");return false;}
  const auto slot=hardware.slot;
  std::array<duint,4> dr{context.Dr0,context.Dr1,context.Dr2,context.Dr3};
  if(dr[slot]&&dr[slot]!=hardware.address){
   if(!addGuard(hardware.address)||!cmd("bphc "+hex(hardware.address)))return false;
   hardwareSyscalls.erase(hardwareSyscalls.begin()+i);
   log("Context uses a borrowed DR slot; that syscall returned to memory guarding.");continue;
  }
  const duint enableMask=duint(3)<<(slot*2),kindMask=duint(15)<<(16+slot*4);
  const duint wanted=(context.Dr7&~(enableMask|kindMask))|(duint(1)<<(slot*2));
  if(dr[slot]!=hardware.address||context.Dr7!=wanted){
   if(!write(address+offsetof(CONTEXT,Dr0)+slot*sizeof(duint),hardware.address)||!write(address+offsetof(CONTEXT,Dr7),wanted))return false;
   infof("Owned DR preserved at continuation","[KozDbg] Preserved owned DR%u across native context continuation; other slots unchanged.\n",slot);
  }
  context.Dr7=wanted;++i;
 }
 return true;
}
static bool restoreTfGuards(DWORD thread,duint exceptionAddress) {
 for(auto it=tfGuardWindows.begin();it!=tfGuardWindows.end();){
  if(it->thread!=thread||(exceptionAddress&&it->exceptionAddress!=exceptionAddress)){++it;continue;}
  for(auto site:it->sites)if(!ownedGuard(site)&&!addGuard(site))return false;
  infof("TF syscall guards restored","[KozDbg] Restored %u syscall guards after TF delivery for tid=%X\n",static_cast<unsigned>(it->sites.size()),thread);
  it=tfGuardWindows.erase(it);
 }
 return true;
}
static bool prepareTfWindow(duint returnAddress) {
 if(!advanced()||!on(7))return true;
 // The invalid-close call is immediately followed by the runtime TF probe.
 // Decode from its live return address; do not keep a sample-specific RVA.
 duint trap=0;
 for(duint pc=returnAddress;pc<returnAddress+64;){
  std::array<unsigned char,4> bytes{};if(!DbgMemRead(pc,bytes.data(),bytes.size()))return false;
  if(bytes==std::array<unsigned char,4>{0x9d,0x0f,0x31,0x90}){trap=pc+3;break;}
  BASIC_INSTRUCTION_INFO info{};DbgDisasmFastAt(pc,&info);
  if(info.size<=0||info.size>15||(info.branch&&!info.call)||bytes[0]==0xc3)return true;
  pc+=info.size;
 }
 if(!trap)return true;
 const DWORD thread=DbgGetThreadId();
 if(std::any_of(tfGuardWindows.begin(),tfGuardWindows.end(),[&](const TfGuardWindow& w){return w.thread==thread&&w.exceptionAddress==trap;}))return true;
 SYSTEM_INFO system{};GetSystemInfo(&system);
 if(!system.dwPageSize||tfGuardWindows.size()>=128)return false;
 const duint firstPage=(trap-3)/system.dwPageSize,lastPage=trap/system.dwPageSize;
 TfGuardWindow window{thread,trap,{}};
 for(auto site:guardedSites)if(site/system.dwPageSize>=firstPage&&site/system.dwPageSize<=lastPage&&ownedGuard(site))window.sites.push_back(site);
 if(window.sites.empty())return true;
 tfGuardWindows.push_back(window);
 // PAGE_GUARD's own single stepping can consume the target's TF exception.
 // Release only our syscall ranges on these pages until that real exception
 // reaches RtlDispatchException; then restore the ranges before the filter.
 for(auto site:window.sites){
  if(!cmd("bpmc "+hex(site))||ownedGuard(site))return false;
  guardedSites.erase(std::remove(guardedSites.begin(),guardedSites.end(),site),guardedSites.end());
 }
 infof("TF syscall guards released","[KozDbg] Temporarily released %u syscall guards sharing the live TF probe page; tid=%X\n",static_cast<unsigned>(window.sites.size()),thread);
 return true;
}
#include "scan_chunks.h"
static bool scanSyscalls() {
 duint base=M::GetMainModuleBase();IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS64 nt{};
 if(!base||!read(base,dos)||dos.e_magic!=IMAGE_DOS_SIGNATURE||dos.e_lfanew<=0){log("Syscall scan: cannot read a valid DOS header.");return false;}
 if(base>std::numeric_limits<duint>::max()-static_cast<duint>(dos.e_lfanew)||!read(base+dos.e_lfanew,nt)||nt.Signature!=IMAGE_NT_SIGNATURE){log("Syscall scan: invalid or unreadable NT header.");return false;}
 if(nt.FileHeader.NumberOfSections==0||nt.FileHeader.NumberOfSections>96){log("Syscall scan: invalid section count (expected 1..96).");return false;}
 const duint tableRva=static_cast<duint>(dos.e_lfanew)+sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER)+nt.FileHeader.SizeOfOptionalHeader;
 const duint tableSize=static_cast<duint>(nt.FileHeader.NumberOfSections)*sizeof(IMAGE_SECTION_HEADER);
 if(base>std::numeric_limits<duint>::max()-nt.OptionalHeader.SizeOfImage||tableRva>nt.OptionalHeader.SizeOfImage||tableSize>nt.OptionalHeader.SizeOfImage-tableRva){log("Syscall scan: section table or image address range is invalid.");return false;}
 duint sections=base+tableRva;
 std::vector<std::pair<duint,duint>> codeRanges;
 bool hasUnbackedCode=false;
 for(unsigned i=0;i<nt.FileHeader.NumberOfSections;i++){
  IMAGE_SECTION_HEADER s{};
  if(!read(sections+i*sizeof(s),s)){logf("[KozDbg] Syscall scan: cannot read section header %u at %p.\n",i,(void*)(sections+i*sizeof(s)));return false;}
  if(!(s.Characteristics&IMAGE_SCN_MEM_EXECUTE))continue;
  const size_t length=s.Misc.VirtualSize;if(!length)continue;
  if(!s.SizeOfRawData)hasUnbackedCode=true;
  if(s.VirtualAddress>=nt.OptionalHeader.SizeOfImage||length>nt.OptionalHeader.SizeOfImage-s.VirtualAddress){logf("[KozDbg] Syscall scan: section %u lies outside SizeOfImage (RVA=%X size=%X).\n",i,s.VirtualAddress,s.Misc.VirtualSize);return false;}
  codeRanges.push_back({base+s.VirtualAddress,base+s.VirtualAddress+length});
  logf("[KozDbg] Scanning section %u (%.8s): %llu bytes in 1 MiB blocks.\n",i,reinterpret_cast<const char*>(s.Name),static_cast<unsigned long long>(length));
  const bool scanned=kozScanChunks(length,[&](size_t offset,unsigned char* data,size_t count){
   const duint address=base+s.VirtualAddress+offset;
   if(DbgMemRead(address,data,count))return true;
   logf("[KozDbg] Syscall scan: read failed in section %u (%.8s) at %p, block size=%llu. Scan aborted; no unreadable bytes skipped.\n",i,reinterpret_cast<const char*>(s.Name),(void*)address,static_cast<unsigned long long>(count));return false;
  },[&](size_t offset){
   if(syscallSites.size()>=2048){logf("[KozDbg] Syscall scan: candidate limit 2048 exceeded in section %u at %p; refusing unbounded instrumentation.\n",i,(void*)(base+s.VirtualAddress+offset));return false;}
   syscallSites.push_back(base+s.VirtualAddress+offset);return true;
  });
  if(!scanned)return false;
 }
 // The 3.6 native-call wrappers form dense syscall islands. Isolated 0F05
 // byte pairs in VM immediates are not instruction boundaries and must not
 // put guard stepping on arbitrary VM handlers (notably PUSHFQ handlers).
 if(profile().engine==Engine::ClusteredSyscalls){
  const auto all=syscallSites;
  syscallSites.erase(std::remove_if(syscallSites.begin(),syscallSites.end(),[&](duint site){
   return std::count_if(all.begin(),all.end(),[&](duint other){return other>=site-0x400&&other<=site+0x400;})<4;
  }),syscallSites.end());
 }else{
  // 3.8 disperses native wrappers: after SYSCALL they resume through a direct
  // call into executable image code or a PUSH-based VM transition. Recognize
  // that continuation, rather than density. Embedded displacement/immediate
  // pairs on hot VM-handler pages must not create per-instruction guard traps.
  syscallSites.erase(std::remove_if(syscallSites.begin(),syscallSites.end(),[&](duint site){
   std::array<unsigned char,5> tail{};if(!DbgMemRead(site+2,tail.data(),tail.size()))return true;
   if((tail[0]>=0x50&&tail[0]<=0x57)||tail[0]==0x68||tail[0]==0x6a||tail[0]==0x9c||
      (tail[0]==0x41&&tail[1]>=0x50&&tail[1]<=0x57))return false;
   if(tail[0]!=0xe8)return true;
   int32_t displacement=0;memcpy(&displacement,tail.data()+1,4);duint target=0;
   if(!relativeAddress(site+2,5,displacement,target))return true;
   return std::none_of(codeRanges.begin(),codeRanges.end(),[&](const auto& r){return target>=r.first&&target<r.second;});
  }),syscallSites.end());
 }
 if(syscallSites.empty()){log("No live syscall candidates were found in the main executable.");return false;}
 // Only consider images with executable content to reconstruct at runtime.
 // Unpacked runtimes can contain a dormant decoder too; keep their DR slots free.
 if(on(12)&&hasUnbackedCode){
  SYSTEM_INFO system{};GetSystemInfo(&system);std::vector<duint> visited;
  if(system.dwPageSize)for(auto site:syscallSites){
   const duint page=site/system.dwPageSize*system.dwPageSize;
   if(std::find(visited.begin(),visited.end(),page)!=visited.end())continue;
   visited.push_back(page);
   std::vector<duint> pageSites;
   for(auto candidate:syscallSites)if(candidate/system.dwPageSize==page/system.dwPageSize)pageSites.push_back(candidate);
   if(pageSites.size()>4||!rangeDecoderPage(page,system.dwPageSize))continue;
   bool complete=true;
   for(auto candidate:pageSites)if(!addHardwareSyscall(candidate)){complete=false;break;}
   if(complete){logf("[KozDbg] Decoder page %p: all %u candidates use hardware breakpoints.\n",(void*)page,static_cast<unsigned>(pageSites.size()));break;}
   // Partial coverage would leave PAGE_GUARD on the hot page anyway.
   for(const auto& hardware:hardwareSyscalls)if(ownedHardware(hardware.address)&&!cmd("bphc "+hex(hardware.address))){log("Cannot roll back partial decoder acceleration; stopping setup.");return false;}
   hardwareSyscalls.clear();log("Not enough safe hardware slots for the complete decoder page; retaining memory coverage.");
  }
 }
 for(auto site:syscallSites){
  const bool accelerated=std::any_of(hardwareSyscalls.begin(),hardwareSyscalls.end(),[&](const HardwareSyscall& h){return h.address==site;});
  if(!accelerated&&!addGuard(site)){logf("[KozDbg] Syscall scan: cannot install guard at %p; check existing breakpoints and page access.\n",(void*)site);return false;}
 }
 logf("[KozDbg] Tracking %u live SYSCALL candidates: %u memory guards, %u hardware slots; protected instructions unchanged.\n",static_cast<unsigned>(syscallSites.size()),static_cast<unsigned>(guardedSites.size()),static_cast<unsigned>(hardwareSyscalls.size()));
 return true;
}
static duint exceptionDispatcherTarget() {
 // Resolve the direct dispatch call from the exported Windows dispatcher.
 // On this x64 form RCX is EXCEPTION_RECORD*, RDX is CONTEXT* from RSP.
 duint start=DbgValFromString("ntdll:KiUserExceptionDispatcher");
 if(!start)return 0;
 for(duint pc=start;pc<start+128;){
  BASIC_INSTRUCTION_INFO info{};DbgDisasmFastAt(pc,&info);if(info.size<=0||info.size>15)return 0;
  std::array<unsigned char,5> bytes{};if(!DbgMemRead(pc,bytes.data(),bytes.size()))return 0;
  if(bytes[0]==0xe8&&info.size==5&&pc>=start+3){
   std::array<unsigned char,3> previous{};
   if(DbgMemRead(pc-3,previous.data(),3)&&previous==std::array<unsigned char,3>{0x48,0x8b,0xd4}){
    int32_t displacement=0;memcpy(&displacement,bytes.data()+1,4);duint target=0;
    if(relativeAddress(pc,5,displacement,target))return target;
   }
  }
  if(bytes[0]==0xc3)break;pc+=info.size;
 }
 return 0;
}
static bool setupLegacyContext() {
 // The 3.3.1 TF filter also consumes saved DR0-DR3. Only install the shared
 // exception/context bindings here: no direct-syscall scan or other advanced
 // API treatment is needed for the API-based profiles.
 if(!on(9))return true;
 advancedPid=GetProcessId(DbgGetProcessHandle());
 const duint dispatcher=exceptionDispatcherTarget();
 if(!dispatcher){log("Unsupported Windows exception-dispatcher layout; profile not armed.");return false;}
 std::vector<ApiBinding> bindings;
 if(!addBinding(bindings,dispatcher,7)||
    !resolveBinding(bindings,"ntdll:NtContinue",8,true)||
    !resolveBinding(bindings,"ntdll:RtlRestoreContext",9,true))return false;
 for(const auto& binding:bindings)if(!addBP(binding.address,std::to_string(binding.action)))return false;
 logf("[KozDbg] Legacy saved-context protection installed; exception dispatch call -> %p.\n",(void*)dispatcher);
 return true;
}
static bool setupDirect() {
 advancedPid=GetProcessId(DbgGetProcessHandle());
 if(on(0)){
  pebByte=DbgGetPebAddress(advancedPid)+2;
  if(pebByte<3||!read(pebByte,savedPebByte)||!write(pebByte,static_cast<unsigned char>(0))){log("Cannot read or clear PEB.BeingDebugged.");return false;}
  count(0,"Direct PEB.BeingDebugged read covered; original byte saved for disable/stop");
 }
 if(!syscallNumber("ntdll:NtQueryInformationProcess",queryProcessSSN)||
    !syscallNumber("ntdll:NtSetInformationThread",setThreadSSN)||
    !syscallNumber("ntdll:NtSetInformationProcess",setProcessSSN)){log("Cannot resolve process/thread syscall numbers from ntdll.");return false;}
 std::vector<ApiBinding> bindings;
 if(on(8)&&!resolveBinding(bindings,"ntdll:NtSetInformationProcess",6,true)){log("Cannot resolve NtSetInformationProcess binding.");return false;}
 if(on(9)||on(7)){
  duint dispatcher=exceptionDispatcherTarget();
  if(!dispatcher){log("Unsupported Windows exception-dispatcher layout; profile not armed.");{log("Exception dispatcher unavailable.");return false;}}
  logf("[KozDbg] Resolved exception dispatch call -> %p\n",(void*)dispatcher);
  if(!addBinding(bindings,dispatcher,7)){log("Cannot register exception-dispatch binding.");return false;}
 }
 if((on(9)||on(12))&&(!resolveBinding(bindings,"ntdll:NtContinue",8,true)||!resolveBinding(bindings,"ntdll:RtlRestoreContext",9,true))){log("Cannot resolve NtContinue/RtlRestoreContext bindings.");return false;}
 if(on(10)){
  remoteBreakin=DbgValFromString("ntdll:DbgUiRemoteBreakin");
  if(!remoteBreakin||!DbgMemRead(remoteBreakin,breakinBytes.data(),breakinBytes.size())||!resolveBinding(bindings,"kernel32:WriteProcessMemory",10,true)){log("Cannot read DbgUiRemoteBreakin or resolve WriteProcessMemory.");return false;}
 }
 if(extendedChecks()){
  if(!syscallNumber("ntdll:NtQuerySystemInformation",querySystemSSN)){log("Cannot resolve NtQuerySystemInformation syscall number.");return false;}
  if(on(3)&&(!syscallNumber("ntdll:NtQueryInformationThread",queryThreadSSN)||!resolveBinding(bindings,"ntdll:NtQueryInformationThread",11,true))){log("Cannot resolve NtQueryInformationThread syscall/binding.");return false;}
  if(on(11)&&(!syscallNumber("ntdll:NtOpenFile",openFileSSN)||!resolveBinding(bindings,"ntdll:NtOpenFile",12,true))){log("Cannot resolve NtOpenFile syscall/binding.");return false;}
 }
 for(const auto& b:bindings)if(!addBP(b.address,std::to_string(b.action))){log("Cannot install direct-check API breakpoint; inspect preceding conflict/setup log.");return false;}
 return scanSyscalls();
}
static void disarmDirect() {
 if(DbgIsDebugging()){
  for(auto p:guardedSites)if(ownedGuard(p))cmd("bpmc "+hex(p));
  if(advancedPid==GetProcessId(DbgGetProcessHandle()))for(const auto& saved:savedContexts){
   CONTEXT current{};
   if(read(saved.address,current)&&current.Rip==saved.exceptionIP&&!(current.Dr0|current.Dr1|current.Dr2|current.Dr3))
    DbgMemWrite(saved.address+offsetof(CONTEXT,Dr0),saved.dr.data(),sizeof(saved.dr));
  }
  if(advancedPid==GetProcessId(DbgGetProcessHandle())&&pebByte){unsigned char current=0;if(read(pebByte,current)&&current==0)write(pebByte,savedPebByte);}
  for(const auto& hardware:hardwareSyscalls)if(ownedHardware(hardware.address))cmd("bphc "+hex(hardware.address));
 }
 hardwareSyscalls.clear();
 guardedSites.clear();syscallSites.clear();savedContexts.clear();tfGuardWindows.clear();pebByte=0;remoteBreakin=0;advancedPid=0;
}
static bool emulateQuery(duint process,duint infoClass,duint buffer,duint size,duint returnLength,duint& result) {
 bool port=infoClass==7&&on(1),object=infoClass==0x1e&&on(2);
 if((!port&&!object)||size!=8||(buffer&7)||!writable(buffer,8)||!isSelfHandle(process,false))return false;
 // Preserve real kernel validation for invalid pointers such as ReturnLength=1.
 if(returnLength&&((returnLength&3)||!writable(returnLength,4)))return false;
 if(!write(buffer,duint(0)))return false;
 if(returnLength&&!write(returnLength,uint32_t(8)))return false;
 result=port?0:0xc0000353;
 count(port?1:2,port?"Self ProcessDebugPort -> success / zero port":"Self debug object -> STATUS_PORT_NOT_SET; ordered output/ReturnLength writes preserved");
 return true;
}
static bool nullCallback(duint process,duint infoClass,duint buffer,duint size) {
 if(!on(8)||infoClass!=0x28||size!=16||!isSelfHandle(process,false))return false;
 std::array<unsigned char,16> bytes{};
 return DbgMemRead(buffer,bytes.data(),bytes.size())&&std::all_of(bytes.begin(),bytes.end(),[](unsigned char b){return b==0;});
}
static bool watchHiddenThread(duint handle,duint infoClass,duint buffer,duint size,duint address,duint sp,duint delta) {
 if(!extendedChecks()||!on(3)||infoClass!=0x11||size!=1)return true;
 DWORD id=selfThreadId(handle);
 if(!id||std::find(hiddenThreads.begin(),hiddenThreads.end(),id)==hiddenThreads.end())return true;
 // Execute the real query first: invalid handles, pointers and lengths must
 // still receive the kernel's own status. Only a successful logical state is adjusted.
 return watchReturn(address,ReturnKind::HiddenThread,buffer,id,sp,delta);
}
static bool titanHideOpen(duint output,duint objectAttributes,duint iosb) {
 if(!extendedChecks()||!on(11)||(output&7)||(iosb&7)||!writable(output,8)||!writable(iosb,16))return false;
 struct Attributes {uint32_t length,pad;duint root,name;uint32_t flags,pad2;duint security,sqos;};
 struct String {uint16_t length,maximum;uint32_t pad;duint buffer;};
 Attributes a{};String s{};
 constexpr wchar_t device[]=L"\\??\\TitanHide";
 if((objectAttributes&7)||!read(objectAttributes,a)||a.length!=sizeof(a)||a.root||a.security||a.sqos||
    (a.name&7)||!read(a.name,s)||s.length!=sizeof(device)-sizeof(wchar_t)||s.maximum<s.length)return false;
 std::array<wchar_t,std::size(device)> name{};
 if(!DbgMemRead(s.buffer,name.data(),s.length))return false;
 bool match=(a.flags&0x40)?_wcsicmp(name.data(),device)==0:wcscmp(name.data(),device)==0;
 if(match)count(11,"Exact TitanHide device open blocked: STATUS_OBJECT_NAME_NOT_FOUND; no device handle or UnhideAll write");
 return match;
}
static bool syscallHit(int,char**) {
 if(!armed||!advanced())return true;
 duint ip=R::GetRIP(),sp=R::GetRSP();
 if(std::find(syscallSites.begin(),syscallSites.end(),ip)==syscallSites.end())return true;
 uint16_t opcode=0;if(!read(ip,opcode)||opcode!=0x050f)return true;
 unsigned ssn=R::GetEAX();duint result=0;bool handled=false;
 if(ssn==queryProcessSSN){duint returnLength=0;if(read(sp+0x28,returnLength))handled=emulateQuery(R::GetR10(),R::GetRDX(),R::GetR8(),R::GetR9(),returnLength,result);}
 else if(ssn==setThreadSSN&&on(3)&&R::GetRDX()==0x11&&R::GetR8()==0&&R::GetR9()==0&&isSelfHandle(R::GetR10(),true)){
  rememberHiddenThread(R::GetR10());
  handled=true;count(3,"Direct-syscall ThreadHideFromDebugger suppressed");
 }else if(ssn==setProcessSSN&&nullCallback(R::GetR10(),R::GetRDX(),R::GetR8(),R::GetR9())){
  handled=true;count(8,"Direct instrumentation-callback clearing suppressed");
 }
 if(extendedChecks()&&!handled){
  bool ok=true;
  if(on(3)&&ssn==queryThreadSSN)ok=watchHiddenThread(R::GetR10(),R::GetRDX(),R::GetR8(),R::GetR9(),ip+2,sp,0);
  else if(ssn==querySystemSSN){
   if(on(4)&&R::GetR10()==0x23&&R::GetR8()>=2)ok=watchReturn(ip+2,ReturnKind::Kernel,R::GetRDX(),R::GetR8(),sp,0);
   else if(on(5)&&R::GetR10()==0xb&&R::GetR8()>=8)ok=watchReturn(ip+2,ReturnKind::Modules,R::GetRDX(),R::GetR8(),sp,0);
  }else if(on(11)&&ssn==openFileSSN&&titanHideOpen(R::GetR10(),R::GetR8(),R::GetR9())){handled=true;result=0xc0000034;}
  if(!ok){log("Cannot monitor a direct-syscall return; paused.");cmd("mov $breakpointcondition,1");return false;}
 }
 if(!handled)return true;
 // SYSCALL clobbers RCX/R11 but leaves the user stack in place. Do not RET
 // from a mutated VM wrapper or assume a static syscall address/service ID.
 duint flags=R::GetCFLAGS();
 bool ok=R::SetRAX(result)&&R::SetRCX(ip+2)&&R::SetR11(flags)&&R::SetRIP(ip+2);
 if(!ok){log("Syscall emulation failed; paused.");cmd("mov $breakpointcondition,1");}
 return ok;
}
static bool trustedTfRecord(duint exceptionAddress) {
 std::array<unsigned char,4> bytes{};
 return exceptionAddress>=3&&DbgMemRead(exceptionAddress-3,bytes.data(),4)&&bytes==std::array<unsigned char,4>{0x9d,0x0f,0x31,0x90};
}
static bool sanitizeContext() {
 EXCEPTION_RECORD record{};CONTEXT context{};
 duint address=R::GetRDX();
 if(!read(R::GetRCX(),record)||record.ExceptionCode!=EXCEPTION_SINGLE_STEP||!trustedTfRecord((duint)record.ExceptionAddress)||
    !read(address,context)||context.Rip!=(duint)record.ExceptionAddress||(context.ContextFlags&CONTEXT_DEBUG_REGISTERS)!=CONTEXT_DEBUG_REGISTERS)return true;
 if(!(context.Dr0|context.Dr1|context.Dr2|context.Dr3))return true;
 if(savedContexts.size()>128)return false;
 SavedDebugContext saved{DbgGetThreadId(),address,R::GetRCX(),context.Rip,{context.Dr0,context.Dr1,context.Dr2,context.Dr3}};
 std::array<duint,4> zero{};
 if(!DbgMemWrite(address+offsetof(CONTEXT,Dr0),zero.data(),sizeof(zero)))return false;
 savedContexts.push_back(saved);count(9,"Saved DR0-DR3 hidden during the program's TF filter; live hardware breakpoints retained");return true;
}
static bool restoreContext(bool rtlRestore) {
 DWORD thread=DbgGetThreadId();
 auto it=std::find_if(savedContexts.rbegin(),savedContexts.rend(),[&](const SavedDebugContext& c){
  return c.thread==thread&&(R::GetRCX()==c.address||(rtlRestore&&R::GetRDX()==c.exceptionRecord));
 });
 if(it==savedContexts.rend())return true;
 std::array<duint,4> current{};duint address=R::GetRCX()+offsetof(CONTEXT,Dr0);
 if(!DbgMemRead(address,current.data(),sizeof(current)))return false;
 if(current==std::array<duint,4>{}&&!DbgMemWrite(address,it->dr.data(),sizeof(it->dr)))return false;
 savedContexts.erase(std::next(it).base());info("Saved DR0-DR3 restored at context continuation");return true;
}
static bool restoreAttach() {
 if(!remoteBreakin||!DbgMemWrite(remoteBreakin,breakinBytes.data(),breakinBytes.size()))return false;
 count(10,"Restored DbgUiRemoteBreakin after a self-process write to its entry");return true;
}
static bool hitDirect(int action,duint,duint sp,duint ra) {
 if(action==11)return watchHiddenThread(R::GetRCX(),R::GetRDX(),R::GetR8(),R::GetR9(),ra,sp,8);
 if(action==12&&titanHideOpen(R::GetRCX(),R::GetR8(),R::GetR9()))return ret(ra,0xc0000034);
 if(action==6&&nullCallback(R::GetRCX(),R::GetRDX(),R::GetR8(),R::GetR9())){
  if(!ret(ra,0))return false;count(8,"Instrumentation-callback clearing suppressed");
 }
 if(action==7){
  if(!tfGuardWindows.empty()){
   EXCEPTION_RECORD record{};if(!read(R::GetRCX(),record))return false;
   if(record.ExceptionCode==EXCEPTION_SINGLE_STEP&&!restoreTfGuards(DbgGetThreadId(),(duint)record.ExceptionAddress))return false;
  }
  if(on(9))return sanitizeContext();
 }
 if(action==8||action==9)return (!on(9)||restoreContext(action==9))&&preserveHardwareContext();
 if(action==10&&on(10)&&isSelfHandle(R::GetRCX(),false)){
  duint destination=R::GetRDX(),size=R::GetR9();
  if(size&&destination<=std::numeric_limits<duint>::max()-size&&destination<remoteBreakin+breakinBytes.size()&&destination+size>remoteBreakin)
   return watchReturn(ra,ReturnKind::Attach,remoteBreakin,breakinBytes.size(),sp);
 }
 return true;
}
