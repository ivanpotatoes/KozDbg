// x64dbg's module breakpoints are keyed by module name + RVA. Its DLL-load
// handler reapplies them to another mapping of the same name; DLL-unload then
// deletes hardware slots by index, including slots belonging to the first map.
// LOAD temporarily shelters entries until its post-core callback. UNLOAD keeps
// entries enabled/live and suppresses only the verified core removal call.
// The debugger event tail closes that protection window before target resume.
// No user DLL breakpoint is created, removed, reconfigured or replayed.
struct ModuleHardwareAlias {std::string name;duint copy=0,original=0;};
struct ModuleHardwareRecord {BRIDGEBP before{};std::string logfile;bool suspended=false;};
enum class ModuleHardwarePhase {None,Load,Unload};
struct ModuleHardwareOperation {
 ModuleHardwarePhase phase=ModuleHardwarePhase::None;
 ModuleHardwareAlias alias;
 std::vector<ModuleHardwareRecord> records;
 DWORD process=0,thread=0,worker=0;
 bool coreRemovalFinished=false;
 unsigned suppressedSlots=0;
};
static std::vector<ModuleHardwareAlias> moduleHardwareAliases;
static ModuleHardwareOperation moduleHardwareOperation;
static std::atomic<bool> moduleHardwareBusy{false};
static std::atomic<bool> moduleHardwarePauseActive{false},moduleHardwareStopping{false};
static unsigned moduleHardwareLoads=0,moduleHardwareUnloads=0,moduleHardwareConflicts=0;

static bool moduleHardwareNameSafe(const std::string& name) {
 return !name.empty()&&name.size()<MAX_MODULE_SIZE&&std::none_of(name.begin(),name.end(),[](unsigned char c){return c<32||c=='"'||c=='\\'||c=='/';});
}
static bool moduleHardwareLoadName(HANDLE file,std::string& name) {
 if(!file||file==INVALID_HANDLE_VALUE)return false;
 std::vector<wchar_t> path(1024);
 DWORD size=GetFinalPathNameByHandleW(file,path.data(),static_cast<DWORD>(path.size()),FILE_NAME_NORMALIZED);
 if(size>=path.size()&&size<32768){path.resize(static_cast<size_t>(size)+1);size=GetFinalPathNameByHandleW(file,path.data(),static_cast<DWORD>(path.size()),FILE_NAME_NORMALIZED);}
 if(!size||size>=path.size())return false;
 const wchar_t* last=wcsrchr(path.data(),L'\\');last=last?last+1:path.data();
 const int required=WideCharToMultiByte(CP_UTF8,0,last,-1,nullptr,0,nullptr,nullptr);
 if(required<=1||required>MAX_MODULE_SIZE)return false;
 std::vector<char> utf8(static_cast<size_t>(required));
 if(!WideCharToMultiByte(CP_UTF8,0,last,-1,utf8.data(),required,nullptr,nullptr))return false;
 name=utf8.data();return moduleHardwareNameSafe(name);
}
static bool moduleHardwareResident(const ModuleHardwareAlias& alias) {
 char name[MAX_MODULE_SIZE]{};
 return alias.original&&M::BaseFromAddr(alias.original)==alias.original&&M::NameFromAddr(alias.original,name)&&_stricmp(name,alias.name.c_str())==0;
}
static bool moduleHardwareSameMetadata(const BRIDGEBP& a,const BRIDGEBP& b) {
 // Enabled/active and the assigned slot may change during the transaction.
 return a.type==b.type&&a.addr==b.addr&&a.typeEx==b.typeEx&&a.hwSize==b.hwSize&&
  a.singleshoot==b.singleshoot&&a.fastResume==b.fastResume&&a.silent==b.silent&&a.hitCount==b.hitCount&&
  strcmp(a.name,b.name)==0&&_stricmp(a.mod,b.mod)==0&&strcmp(a.breakCondition,b.breakCondition)==0&&
  strcmp(a.logText,b.logText)==0&&strcmp(a.logCondition,b.logCondition)==0&&
  strcmp(a.commandText,b.commandText)==0&&strcmp(a.commandCondition,b.commandCondition)==0;
}
static bool moduleHardwareLogfile(duint address,std::string& value) {
 BP_REF ref{};
 return DbgFunctions()->BpRefVa(&ref,bp_hardware,address)&&ref.GetField(bpf_logfile,value);
}
static bool moduleHardwareMatches(const ModuleHardwareRecord& saved,const BRIDGEBP& current) {
 std::string logfile;
 return moduleHardwareSameMetadata(saved.before,current)&&moduleHardwareLogfile(saved.before.addr,logfile)&&logfile==saved.logfile;
}
static bool moduleHardwareSnapshot(ModuleHardwareOperation& operation) {
 if(!moduleHardwareResident(operation.alias))return false;
 const auto originalSize=M::SizeFromAddr(operation.alias.original);
 BPMAP map{};DbgGetBpList(bp_hardware,&map);bool ok=true;unsigned slots=0;
 for(int i=0;i<map.count;i++){
  const auto& listed=map.bp[i];
  if(!listed.enabled||_stricmp(listed.mod,operation.alias.name.c_str())!=0)continue;
  const duint listedBase=M::BaseFromAddr(listed.addr);
  if(!listedBase||listed.addr<listedBase||listed.addr-listedBase>=originalSize){ok=false;break;}
  // List addresses may point at the lower-address duplicate. Pin the original
  // mapping and retrieve metadata by its exact VA instead of a module symbol.
  const duint address=operation.alias.original+(listed.addr-listedBase);
  BRIDGEBP current{};
  if(!DbgFunctions()->GetBridgeBp(bp_hardware,address,&current)||!current.enabled||current.slot>=4||
     (slots&(1u<<current.slot))||operation.records.size()>=4){ok=false;break;}
  std::string logfile;
  if(!moduleHardwareLogfile(address,logfile)){ok=false;break;}
  slots|=1u<<current.slot;operation.records.push_back({current,std::move(logfile),false});
 }
 if(map.bp)BridgeFree(map.bp);
 std::sort(operation.records.begin(),operation.records.end(),[](const ModuleHardwareRecord& a,const ModuleHardwareRecord& b){return a.before.slot<b.before.slot;});
 return ok;
}
static bool moduleHardwareRestore(ModuleHardwareOperation& operation) {
 bool ok=true;unsigned slots=0;
 for(auto& saved:operation.records){
  if(!saved.suspended)continue;
  BRIDGEBP current{};
  if(!moduleHardwareResident(operation.alias)||!DbgFunctions()->GetBridgeBp(bp_hardware,saved.before.addr,&current)||
     !moduleHardwareMatches(saved,current)){
   logf("[KozDbg] Module hardware restore conflict at %p; changed/deleted analyst entry left untouched.\n",(void*)saved.before.addr);ok=false;continue;
  }
  if(!current.enabled&&!cmd("bphwe "+hex(saved.before.addr))){ok=false;continue;}
  if(!DbgFunctions()->GetBridgeBp(bp_hardware,saved.before.addr,&current)||!current.enabled||current.slot>=4||
     (slots&(1u<<current.slot))||!moduleHardwareMatches(saved,current)){ok=false;continue;}
  slots|=1u<<current.slot;saved.suspended=false;
  for(auto& hardware:hardwareSyscalls)if(hardware.address==saved.before.addr)hardware.slot=current.slot;
  infof("Module hardware breakpoint restored","[KozDbg] Restored module hardware breakpoint %p in DR%u; analyst metadata and hit count retained.\n",(void*)current.addr,current.slot);
 }
 return ok;
}
static bool moduleHardwareSuspend(ModuleHardwareOperation& operation) {
 for(auto& saved:operation.records){
  BRIDGEBP current{};
  if(!DbgFunctions()->GetBridgeBp(bp_hardware,saved.before.addr,&current)||!current.enabled||
     !moduleHardwareMatches(saved,current))return false;
  // From this point the command may have changed the entry even if it reports
  // failure or readback fails. Keep the rollback obligation until verified.
  saved.suspended=true;
  const bool disabled=cmd("bphwd "+hex(saved.before.addr));
  if(!disabled||!DbgFunctions()->GetBridgeBp(bp_hardware,saved.before.addr,&current)||current.enabled||
     !moduleHardwareMatches(saved,current))return false;
 }
 return true;
}
static void moduleHardwareComplete(const char* checkpoint) {
 if(moduleHardwareOperation.phase==ModuleHardwarePhase::Load)++moduleHardwareLoads;
 else if(moduleHardwareOperation.phase==ModuleHardwarePhase::Unload)++moduleHardwareUnloads;
 infof("Duplicate module hardware repair completed","[KozDbg] Duplicate module hardware repair completed at %s; DLL breakpoint settings untouched.\n",checkpoint);
 moduleHardwareOperation={};
}
static bool moduleHardwareSuppressDelete(DWORD index) {
 // Public TitanEngine register IDs UE_DR0..UE_DR3 are 11..14.
 if(index<11||index>14||moduleHardwareBusy.exchange(true))return false;
 bool suppress=false;const unsigned slot=index-11;
 if(moduleHardwareOperation.phase==ModuleHardwarePhase::Unload&&!moduleHardwareOperation.coreRemovalFinished&&
    moduleHardwareOperation.worker==GetCurrentThreadId()&&!moduleHardwareStopping&&moduleHardwareResident(moduleHardwareOperation.alias)){
  for(const auto& saved:moduleHardwareOperation.records){
   BRIDGEBP current{};
   // Names/conditions/log settings may be edited during a pre-core pause.
   // Keep an enabled breakpoint at the same original mapping/address/slot;
   // disabled/deleted entries or changed slot identities must still forward.
   if(!DbgFunctions()->GetBridgeBp(bp_hardware,saved.before.addr,&current)||!current.enabled||current.type!=bp_hardware||
      current.addr!=saved.before.addr||current.slot!=saved.before.slot||current.slot!=slot||
      _stricmp(current.mod,moduleHardwareOperation.alias.name.c_str())!=0||
      M::BaseFromAddr(current.addr)!=moduleHardwareOperation.alias.original)continue;
   const std::array<duint,4> live{R::GetDR0(),R::GetDR1(),R::GetDR2(),R::GetDR3()};
   if(live[slot]!=saved.before.addr)continue;
   moduleHardwareOperation.suppressedSlots|=1u<<slot;suppress=true;
   infof("Original module DR preserved","[KozDbg] Preserved original DR%u at %p; suppressed duplicate-module core removal only.\n",slot,(void*)saved.before.addr);
   break;
  }
 }
 moduleHardwareBusy=false;return suppress;
}
static bool clearModuleHardware() {
 if(moduleHardwareBusy.exchange(true)){log("Module hardware transaction is in progress; cleanup must wait.");return false;}
 if(moduleHardwareOperation.phase==ModuleHardwarePhase::Unload&&!moduleHardwareOperation.coreRemovalFinished&&
    !moduleHardwareStopping&&DbgIsDebugging()){
  moduleHardwareBusy=false;log("The pending DLL event has not reached its completion checkpoint; resume or stop before reapplying.");return false;
 }
 bool ok=true;
 if(moduleHardwareOperation.phase!=ModuleHardwarePhase::None&&DbgIsDebugging()&&
    moduleHardwareOperation.process==GetProcessId(DbgGetProcessHandle())){
  ok=moduleHardwareRestore(moduleHardwareOperation);
  if(!ok)log("Module hardware cleanup incomplete; records retained. Stop the session before unloading.");
 }
 if(ok){moduleHardwareOperation={};moduleHardwareAliases.clear();}
 moduleHardwareBusy=false;return ok;
}
static void moduleHardwarePauseRecovery() {
 if(!DbgIsDebugging()||moduleHardwareStopping)return;
 moduleHardwarePauseActive=true;
 log("Module hardware recovery is incomplete. Paused before target resume; inspect the records or stop the session.");
 _plugin_debugpause();
 moduleHardwarePauseActive=false;
}
static bool moduleHardwareVerifyLive() {
 const std::array<duint,4> live{R::GetDR0(),R::GetDR1(),R::GetDR2(),R::GetDR3()};
 const duint enable=R::GetDR7();
 for(const auto& saved:moduleHardwareOperation.records){
  BRIDGEBP current{};
  // A user's DLL condition/command may intentionally change this entry.
  // Honor it. Verify only the still-enabled, unchanged analyst entries.
  if(!DbgFunctions()->GetBridgeBp(bp_hardware,saved.before.addr,&current)||!current.enabled||
     !moduleHardwareMatches(saved,current))continue;
  if(current.slot>=4||live[current.slot]!=current.addr||!(enable&(duint(3)<<(current.slot*2)))){
   logf("[KozDbg] Unchanged hardware entry %p is missing from its live slot; refusing target resume.\n",(void*)current.addr);return false;
  }
 }
 return true;
}
static bool moduleHardwareTail(DWORD process,DWORD thread) {
 // Called by TitanEngine's local IAT checkpoint after core DLL processing,
 // before the OS can resume any debuggee thread. It also covers fast-resume.
 for(;;){
  if(moduleHardwareStopping)return true;
  if(moduleHardwareBusy.exchange(true)){
   log("Event-tail hardware recovery overlapped another transaction; refusing to resume the target.");return false;
  }
  if(moduleHardwareOperation.phase==ModuleHardwarePhase::None||moduleHardwareOperation.process!=process){moduleHardwareBusy=false;return true;}
  if(moduleHardwareOperation.thread!=thread){
   moduleHardwareBusy=false;log("Event-tail thread does not match the pending DLL event; target resume refused.");return false;
  }
  const bool restored=moduleHardwareRestore(moduleHardwareOperation)&&
   (moduleHardwareOperation.phase!=ModuleHardwarePhase::Unload||moduleHardwareVerifyLive());
  if(restored)moduleHardwareComplete("ContinueDebugEvent");
  else ++moduleHardwareConflicts;
  moduleHardwareBusy=false;
  if(restored)return true;
  // An explicit resume retries instead of silently forwarding missing slots.
  // Stopping the debug session cancels the pending process-local transaction.
  moduleHardwarePauseRecovery();
  if(!DbgIsDebugging())return true;
 }
}
static void moduleHardwareEvent(CBTYPE type,void* info) {
 // cbDebugDetach emits CB_DETACH before dbgdetachDisableAllBreakpoints and
 // DetachDebuggerEx. Those remove live slots without disabling DB records;
 // the old event tail must not interpret detach cleanup as lost hardware.
 if(type==CB_STOPPINGDEBUG||type==CB_DETACH||type==CB_EXITPROCESS)moduleHardwareStopping=true;
 else if(type==CB_INITDEBUG)moduleHardwareStopping=false;
 if(!info||moduleHardwareBusy.exchange(true))return;
 if(!armed&&moduleHardwareOperation.phase==ModuleHardwarePhase::None){moduleHardwareBusy=false;return;}
 if(moduleHardwareOperation.phase!=ModuleHardwarePhase::None&&DbgIsDebugging()&&
    moduleHardwareOperation.process!=GetProcessId(DbgGetProcessHandle())){
  log("Discarding module hardware state from an ended session.");
  moduleHardwareOperation={};moduleHardwareAliases.clear();
 }
 bool pauseForFailure=false;
 if(type==CB_DEBUGEVENT&&armed){
  const auto event=static_cast<PLUG_CB_DEBUGEVENT*>(info)->DebugEvent;
  if(event&&event->dwDebugEventCode==LOAD_DLL_DEBUG_EVENT){
   std::string name;
   if(moduleHardwareLoadName(event->u.LoadDll.hFile,name)){
    const duint copy=(duint)event->u.LoadDll.lpBaseOfDll;
    duint original=0;
    for(const auto& alias:moduleHardwareAliases)if(_stricmp(alias.name.c_str(),name.c_str())==0&&moduleHardwareResident(alias)){original=alias.original;break;}
    if(!original)original=M::BaseFromName(name.c_str());
    if(original&&original!=copy){
     ModuleHardwareAlias alias{name,copy,original};
     if(moduleHardwareAliases.size()>=64||moduleHardwareOperation.phase!=ModuleHardwarePhase::None){
      ++moduleHardwareConflicts;log("Duplicate module tracking is busy/full.");pauseForFailure=true;
     }else if(moduleHardwareResident(alias)){
      moduleHardwareAliases.push_back(alias);
      ModuleHardwareOperation operation;operation.phase=ModuleHardwarePhase::Load;operation.alias=alias;
      operation.process=event->dwProcessId;operation.thread=event->dwThreadId;
      if(!moduleHardwareSnapshot(operation)){++moduleHardwareConflicts;log("Cannot snapshot duplicate-module hardware entries.");pauseForFailure=true;}
      else if(!operation.records.empty()){
       if(moduleHardwareSuspend(operation)){
        moduleHardwareOperation=std::move(operation);
        infof("Hardware entries sheltered for duplicate load","[KozDbg] Sheltered %u hardware entries before duplicate %s load %p; original %p.\n",static_cast<unsigned>(moduleHardwareOperation.records.size()),name.c_str(),(void*)copy,(void*)original);
       }else{
        if(!moduleHardwareRestore(operation))moduleHardwareOperation=std::move(operation);
        ++moduleHardwareConflicts;pauseForFailure=true;log("Duplicate load suspension failed; incomplete rollback retained.");
       }
      }
     }
    }
   }
  }
 }else if(type==CB_LOADDLL){
  const duint base=(duint)static_cast<PLUG_CB_LOADDLL*>(info)->LoadDll->lpBaseOfDll;
  if(moduleHardwareOperation.phase==ModuleHardwarePhase::Load&&moduleHardwareOperation.alias.copy==base){
   if(moduleHardwareRestore(moduleHardwareOperation))moduleHardwareComplete("post-LOAD callback");
   else{++moduleHardwareConflicts;pauseForFailure=true;}
  }
 }else if(type==CB_UNLOADDLL&&armed){
  const duint base=(duint)static_cast<PLUG_CB_UNLOADDLL*>(info)->UnloadDll->lpBaseOfDll;
  auto it=std::find_if(moduleHardwareAliases.begin(),moduleHardwareAliases.end(),[&](const ModuleHardwareAlias& a){return a.copy==base;});
  if(it!=moduleHardwareAliases.end()){
   ModuleHardwareOperation operation;operation.phase=ModuleHardwarePhase::Unload;operation.alias=*it;
   operation.process=GetProcessId(DbgGetProcessHandle());operation.thread=DbgGetThreadId();operation.worker=GetCurrentThreadId();
   moduleHardwareAliases.erase(it);
   if(moduleHardwareOperation.phase!=ModuleHardwarePhase::None){++moduleHardwareConflicts;pauseForFailure=true;log("Duplicate unload encountered with pending hardware recovery.");}
   else if(moduleHardwareResident(operation.alias)){
    if(!moduleHardwareSnapshot(operation)){++moduleHardwareConflicts;pauseForFailure=true;}
    else if(!operation.records.empty()){
     moduleHardwareOperation=std::move(operation);
     infof("Hardware entries protected for duplicate unload","[KozDbg] Protecting %u live hardware entries during duplicate %s unload; DLL breakpoint conditions retain live DR values.\n",static_cast<unsigned>(moduleHardwareOperation.records.size()),moduleHardwareOperation.alias.name.c_str());
    }
   }
  }
  moduleHardwareAliases.erase(std::remove_if(moduleHardwareAliases.begin(),moduleHardwareAliases.end(),[&](const ModuleHardwareAlias& a){return a.original==base;}),moduleHardwareAliases.end());
 }else if(moduleHardwareOperation.phase==ModuleHardwarePhase::Unload){
  // Only a matching DLL breakpoint proves core removal has completed.
  // A generic pause could instead come from another pre-unload callback.
  if(type==CB_BREAKPOINT){
   const auto bp=static_cast<PLUG_CB_BREAKPOINT*>(info)->breakpoint;
   if(bp&&bp->type==bp_dll&&_stricmp(bp->mod,moduleHardwareOperation.alias.name.c_str())==0)
    moduleHardwareOperation.coreRemovalFinished=true;
  }
 }
 moduleHardwareBusy=false;
 if(pauseForFailure)moduleHardwarePauseRecovery();
}
