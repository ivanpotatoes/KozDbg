static std::vector<duint> nativeSites;
static bool nativePhase=false,nativeSeen=false;
static std::vector<duint> nativeHardware;
static std::vector<std::pair<unsigned,duint>> retiredNativeSlots;
static uint32_t nativeQuery=0,nativeThread=0,nativeProcess=0,nativeSystem=0,nativeClose=0;
static bool clearNativeSites(bool hardware=true);
static std::vector<duint> nativeGuards;
static duint nativeHardwarePage=0;
static bool nativeCoverageFault=false;
static bool nativeMemoryFallback=false;
static std::vector<duint> nativeGateSites;
static bool nativeWindow=false;
static bool nativeWindowEntered=false;
static unsigned nativeWindowEvents=0;
static duint nativeLastQueryBuffer=0;
static duint nativeHotGate=0;
static DWORD nativeHardwareStepThread=0;
struct NativePageProtection {duint page;DWORD original,guarded;};
static std::vector<NativePageProtection> nativePageProtections;
static bool nativeProtection(duint page,DWORD& protection){
 MEMORY_BASIC_INFORMATION info{};
 if(!VirtualQueryEx(DbgGetProcessHandle(),reinterpret_cast<void*>(page),&info,sizeof(info))||info.State!=MEM_COMMIT)return false;
 protection=info.Protect;return true;
}
static bool removeNativeMemory(duint page){
 const auto it=std::find_if(nativePageProtections.begin(),nativePageProtections.end(),[&](const NativePageProtection& p){return p.page==page;});
 DWORD current=0;
 if(it!=nativePageProtections.end()&&!nativeProtection(page,current))return false;
 // TitanEngine remembers protection from breakpoint creation. The unpacker
 // may have changed it since then. Preserve an observable target change,
 // but not the engine's guard or its temporary single-step restoration.
 const bool changed=it!=nativePageProtections.end()&&current!=it->original&&current!=it->guarded;
 if(!cmd("bpmc "+hex(page)))return false;
 if(changed){
  DWORD previous=0,verified=0;
  if(!VirtualProtectEx(DbgGetProcessHandle(),reinterpret_cast<void*>(page),0x1000,current,&previous)||
   !nativeProtection(page,verified)||verified!=current){
   log("Cannot preserve changed page protection at %08X: requested=%X",page,current);return false;
  }
  log("Preserved target page protection at %08X: %X -> %X",page,it->original,current);
 }
 if(it!=nativePageProtections.end())nativePageProtections.erase(it);
 return true;
}
static bool addNativeMemory(duint page){
 DWORD original=0,guarded=0;if(!nativeProtection(page,original))return false;
 if(!cmd("bpmrange "+hex(page)+",1000,x"))return false;
 if(!nativeProtection(page,guarded)){cmd("bpmc "+hex(page));return false;}
 const auto it=std::find_if(nativePageProtections.begin(),nativePageProtections.end(),[&](const NativePageProtection& p){return p.page==page;});
 const NativePageProtection record{page,original,guarded};
 if(it==nativePageProtections.end())nativePageProtections.push_back(record);else *it=record;
 return true;
}
// x32dbg relocates saved breakpoint addresses with ASLR, but leaves names intact.
static bool nativeBindingName(const char* name,const char* prefix){
 const size_t length=strlen(prefix);if(strncmp(name,prefix,length))return false;
 const char* suffix=name+length;const size_t count=strlen(suffix);if(!count||count>8)return false;
 return std::all_of(suffix,suffix+count,[](unsigned char c){return (c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f');});
}
static duint nativePage(duint at){return at&~duint(0xfff);}
static bool nativeBindingSettings(const BRIDGEBP& bp,unsigned action){
 if(!bp.silent)return false;
 if(!action)return !strcmp(bp.breakCondition,"0")&&!bp.commandText[0];
 const auto number=std::to_string(action);
 if(bp.fastResume)return !bp.commandText[0]&&("kz32_native(0x"+hex(action)+")")==bp.breakCondition;
 return !strcmp(bp.breakCondition,"0")&&!strcmp(bp.commandCondition,"1")&&("kz32_hit "+number)==bp.commandText;
}
static bool configureNativeBinding(BPXTYPE type,duint at,const std::string& name,const char* command){
 BP_REF ref{};auto functions=DbgFunctions();
 unsigned action=0;if(*command&&sscanf_s(command,"kz32_hit %u",&action)!=1)return false;
 const auto condition=action?"kz32_native(0x"+hex(action)+")":std::string("0");
 return functions->BpRefVa(&ref,type,at)&&
  functions->BpSetFieldText(&ref,bpf_name,name.c_str())&&
  functions->BpSetFieldText(&ref,bpf_breakcondition,condition.c_str())&&
  functions->BpSetFieldText(&ref,bpf_commandtext,"")&&
  functions->BpSetFieldText(&ref,bpf_commandcondition,"1")&&
  functions->BpSetFieldNumber(&ref,bpf_fastresume,1)&&
  functions->BpSetFieldNumber(&ref,bpf_silent,1);
}
static bool nativeOwnGateGuard(duint at){
 BRIDGEBP bp{};
 return DbgFunctions()->GetBridgeBp(bp_memory,nativePage(at),&bp)&&nativeBindingName(bp.name,"KZ_G32_")&&
  nativeBindingSettings(bp,13);
}
static bool nativeOwnGate(duint at){
 BRIDGEBP bp{};
 if(DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)&&nativeBindingName(bp.name,"KZ_G64_")&&
  nativeBindingSettings(bp,12))return true;
 return nativeOwnGateGuard(at);
}
static bool clearNativeGates(){
 bool ok=true;
 for(auto it=nativeGateSites.begin();it!=nativeGateSites.end();){
  BRIDGEBP bp{};if(!DbgFunctions()->GetBridgeBp(bp_memory,nativePage(*it),&bp)){it=nativeGateSites.erase(it);continue;}
  if(!nativeOwnGateGuard(*it)||!removeNativeMemory(nativePage(*it))){ok=false;++it;continue;}
  it=nativeGateSites.erase(it);
 }return ok;
}
static bool nativeOwnGuard(duint at);
static bool armNativeGates(duint onlyPage=0){
 for(auto at:nativeGateSites){
  if(onlyPage&&(at&~duint(0xfff))!=onlyPage)continue;
  if(std::find(nativeHardware.begin(),nativeHardware.end(),at)!=nativeHardware.end())continue;
  for(auto it=nativeGuards.begin();it!=nativeGuards.end();){
   if(nativePage(*it)!=nativePage(at)){++it;continue;}
   if(!nativeOwnGuard(*it)||!removeNativeMemory(*it))return false;
   it=nativeGuards.erase(it);
  }
  BRIDGEBP bp{};if(DbgFunctions()->GetBridgeBp(bp_memory,nativePage(at),&bp)){
   if(!nativeOwnGateGuard(at)){log("Existing memory binding prevents gate coverage at %08X",nativePage(at));return false;}
   continue;
  }
  const auto a=hex(nativePage(at));
  if(!addNativeMemory(nativePage(at)))return false;
  const bool configured=configureNativeBinding(bp_memory,nativePage(at),"KZ_G32_"+a,"kz32_hit 13")&&nativeOwnGateGuard(at);
  if(!configured){removeNativeMemory(nativePage(at));log("Gate page setup failed at %08X",nativePage(at));return false;}
 }return !nativeGateSites.empty();
}
static bool refreshNativeGates(){
 GuiDisableUpdateScope updates(false);
 for(auto at:nativeGateSites){
  BRIDGEBP bp{};if(!DbgFunctions()->GetBridgeBp(bp_memory,nativePage(at),&bp))continue;
  if(!nativeOwnGateGuard(at)||!removeNativeMemory(nativePage(at)))return false;
 }
 return armNativeGates();
}
static DWORD nativeGuardThread=0,nativeGuardCode=0;
static duint nativeGuardIp=0;
static bool nativeOwnHardware(duint at){
 BRIDGEBP bp{};if(!DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp))return false;
 return (nativeBindingName(bp.name,"KZ_N64_")&&nativeBindingSettings(bp,0))||
  (nativeBindingName(bp.name,"KZ_G64_")&&nativeBindingSettings(bp,12))||
  (nativeBindingName(bp.name,"KZ_R32_")&&nativeBindingSettings(bp,17));
}
static bool nativeOccupiedSlots(unsigned& occupied){
 occupied=0;duint count=0;const auto functions=DbgFunctions();
 auto refs=functions->BpRefList(&count);if(count&&!refs)return false;
 bool ok=true;
 for(duint i=0;i<count;i++)if(refs[i].type==bp_hardware){
  duint slot=0;if(!functions->BpGetFieldNumber(&refs[i],bpf_hwslot,&slot)){ok=false;break;}
  if(slot<4)occupied|=1u<<slot;
 }
 if(refs)BridgeFree(refs);return ok;
}
static bool nativeOwnGuard(duint at){
 BRIDGEBP bp{};return DbgFunctions()->GetBridgeBp(bp_memory,nativePage(at),&bp)&&
  nativeBindingName(bp.name,"KZ_N32_")&&nativeBindingSettings(bp,14);
}
static bool clearNativeHardware(HANDLE thread=nullptr,duint onlyPage=0){
 if(!thread&&DbgIsDebugging()&&!DbgIsRunning())thread=DbgGetThreadHandle();
 bool ok=true;
 for(auto it=nativeHardware.begin();it!=nativeHardware.end();){
  if(onlyPage&&(*it&~duint(0xfff))!=onlyPage){++it;continue;}
  BRIDGEBP current{};
  if(!DbgFunctions()->GetBridgeBp(bp_hardware,*it,&current)){it=nativeHardware.erase(it);continue;}
  if(!nativeOwnHardware(*it)||current.slot>=4){ok=false;++it;continue;}
  const std::pair<unsigned,duint> retired{current.slot,*it};
  if(std::find(retiredNativeSlots.begin(),retiredNativeSlots.end(),retired)==retiredNativeSlots.end())retiredNativeSlots.push_back(retired);
  if(!cmd("bphc "+hex(*it))){ok=false;++it;continue;}
  if(thread){
   KozWow64::Context actual;
   if(!KozWow64::get(thread,actual)){ok=false;++it;continue;}
   const auto offset=72+8*current.slot;
   if(actual.q(offset)==*it){
    actual.q(offset,0);actual.q(112,actual.q(112)&~((3ull<<(2*current.slot))|(15ull<<(16+4*current.slot))));
    actual.q(104,actual.q(104)&~(1ull<<current.slot));
    if(!KozWow64::setDebug(thread,actual)){ok=false;++it;continue;}
   }
  }
  it=nativeHardware.erase(it);
 }
 if(ok)nativeHardwarePage=0;return ok;
}
static bool reconcileRetiredNativeSlots(HANDLE thread,KozWow64::Context& actual){
 if(retiredNativeSlots.empty()&&nativeHardware.empty())return true;
 unsigned occupied=0;if(!nativeOccupiedSlots(occupied))return false;
 CONTEXT wow{};wow.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if(!GetThreadContext(thread,&wow))return false;
 DWORD* registers[]={&wow.Dr0,&wow.Dr1,&wow.Dr2,&wow.Dr3};
 bool nativeChanged=false,wowChanged=false;
 for(const auto& retired:retiredNativeSlots){
  const auto slot=retired.first;if(occupied&(1u<<slot))continue;
  const auto mask=(3ull<<(slot*2))|(15ull<<(16+slot*4));
  if(actual.q(72+slot*8)==retired.second){
   actual.q(72+slot*8,0);actual.q(112,actual.q(112)&~mask);actual.q(104,actual.q(104)&~(1ull<<slot));nativeChanged=true;
  }
  if(*registers[slot]==retired.second){*registers[slot]=0;wow.Dr7&=~static_cast<DWORD>(mask);wow.Dr6&=~(1u<<slot);wowChanged=true;}
 }
 // Exception continuations and WOW64 context switches can reinstate a prior
 // debug-register snapshot after our page cache moved. Reconcile only slots
 // still owned by the plugin; the debugger's user bindings remain authoritative.
 bool repaired=false;
 for(auto at:nativeHardware){
  BRIDGEBP bp{};
  if(!nativeOwnHardware(at)||!DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)||bp.slot>=4)return false;
  const auto slot=bp.slot;const auto mask=(3ull<<(slot*2))|(15ull<<(16+slot*4));
  const auto slotEnable=1ull<<(slot*2);
  if(actual.q(72+slot*8)!=at||(actual.q(112)&mask)!=slotEnable){
   actual.q(72+slot*8,at);actual.q(112,(actual.q(112)&~mask)|slotEnable);nativeChanged=true;repaired=true;
  }
  if(*registers[slot]!=at||(wow.Dr7&static_cast<DWORD>(mask))!=slotEnable){
   *registers[slot]=at;wow.Dr7=(wow.Dr7&~static_cast<DWORD>(mask))|static_cast<DWORD>(slotEnable);wowChanged=true;repaired=true;
  }
 }
 if(wowChanged&&!SetThreadContext(thread,&wow))return false;
 if(nativeChanged&&!KozWow64::setDebug(thread,actual))return false;
 if(nativeChanged||wowChanged){
  KozWow64::Context verified;
  if(!KozWow64::get(thread,verified))return false;
  for(auto at:nativeHardware){BRIDGEBP bp{};
   if(!DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)||bp.slot>=4||verified.q(72+8*bp.slot)!=at||!((verified.q(112)>>(2*bp.slot))&3))return false;
  }
  log(repaired?"Plugin DR slots synchronized after context restore; user slots preserved":"Retired plugin DR slots cleared from WOW64 context; active breakpoint slots preserved");
 }
 return true;
}
static bool armNativeGuards(bool includeHardware=false,duint onlyPage=0){
 GuiDisableUpdateScope updates(false);
 for(auto at:nativeSites){
  if(onlyPage&&(at&~duint(0xfff))!=onlyPage)continue;
  if(nativeOwnGateGuard(at))continue;
  if(!includeHardware&&std::find(nativeHardware.begin(),nativeHardware.end(),at)!=nativeHardware.end())continue;
  at=nativePage(at);
  if(std::find(nativeGuards.begin(),nativeGuards.end(),at)!=nativeGuards.end()){
   if(!nativeOwnGuard(at))return false;continue;
  }
  BRIDGEBP old{};if(DbgFunctions()->GetBridgeBp(bp_memory,at,&old)){
   log("Existing memory breakpoint conflicts with native coverage at %08X; not modified",at);return false;
  }
  const auto a=hex(at);if(!addNativeMemory(at))return false;
  nativeGuards.push_back(at);
  if(!configureNativeBinding(bp_memory,at,"KZ_N32_"+a,"kz32_hit 14")||!nativeOwnGuard(at))return false;
 }
 return true;
}
static bool armNativeHardwarePage(duint ip,HANDLE eventThread,bool gate=false){
 GuiDisableUpdateScope updates(false);
 GuiDisableLogScope commandLog;
 SYSTEM_INFO system{};GetSystemInfo(&system);if(!system.dwPageSize)return false;
 const auto page=ip/system.dwPageSize*system.dwPageSize;
 std::vector<duint> needed;
 for(auto at:(gate?nativeGateSites:nativeSites))if(at/system.dwPageSize==page/system.dwPageSize)needed.push_back(at);
 if(gate&&nativeWindow)for(auto at:nativeSites)if(nativePage(at)==page&&std::find(needed.begin(),needed.end(),at)==needed.end())needed.push_back(at);
 if(needed.empty())return true;
 if(std::all_of(needed.begin(),needed.end(),[](duint at){return std::find(nativeHardware.begin(),nativeHardware.end(),at)!=nativeHardware.end();})){
  KozWow64::Context actual;
  if(!KozWow64::get(eventThread,actual))return false;
  const std::array<uint64_t,4> live{actual.q(72),actual.q(80),actual.q(88),actual.q(96)};
  const auto control=actual.q(112);
  for(auto at:nativeHardware){BRIDGEBP bp{};
   if(!nativeOwnHardware(at)||!DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)||bp.slot>=4)return false;
   if(live[bp.slot]!=at||!((control>>(2*bp.slot))&3)){
    log("Native slot mismatch: site=%08X slot=%u live=%llX DR7=%llX",at,bp.slot,live[bp.slot],control);return false;
   }
  }
  nativeHardwarePage=page;return true;
 }
 // Keep coverage on several hot pages instead of rotating a single DR slot
 // on every VM-handler transition. Evict only our oldest page when full.
 const auto newCount=std::count_if(needed.begin(),needed.end(),[](duint at){return std::find(nativeHardware.begin(),nativeHardware.end(),at)==nativeHardware.end();});
 for(;;){
  unsigned slots=0;if(!nativeOccupiedSlots(slots))return false;
  unsigned freeSlots=0;for(unsigned i=0;i<4;i++)if(!(slots&(1u<<i)))++freeSlots;
  if(static_cast<unsigned>(newCount)<=freeSlots)break;
  if(nativeHardware.empty())return false;
  const auto victim=std::find_if(nativeHardware.begin(),nativeHardware.end(),[&](duint at){return nativePage(at)!=page;});
  if(victim==nativeHardware.end())return false;
  const auto evicted=*victim/system.dwPageSize*system.dwPageSize;
  if(evicted==page||!clearNativeHardware(eventThread,evicted)||
   (gateProfile()&&!armNativeGates(evicted))||((!gateProfile()||nativeWindow)&&!armNativeGuards(false,evicted)))return false;
 }
 unsigned occupied=0;if(!nativeOccupiedSlots(occupied))return false;
 KozWow64::Context beforeContext;
 if(!KozWow64::get(eventThread,beforeContext))return false;
 const std::array<uint64_t,4> before{beforeContext.q(72),beforeContext.q(80),beforeContext.q(88),beforeContext.q(96)};
 const auto dr7=beforeContext.q(112);unsigned available=0;
 for(unsigned i=0;i<4;i++){
  if((before[i]||((dr7>>(2*i))&3))&&!(occupied&(1u<<i))){
   log("Unmanaged DR%u is occupied; native page coverage was not installed",i);return false;
  }
  if(!(occupied&(1u<<i)))++available;
 }
 if(static_cast<unsigned>(newCount)>available){log("Native page %08X needs %u slots; only %u are free. User breakpoints retained",page,static_cast<unsigned>(newCount),available);return false;}
 for(auto at:needed){
  if(std::find(nativeHardware.begin(),nativeHardware.end(),at)!=nativeHardware.end())continue;
  BRIDGEBP bp{};if(DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp))return false;
  const auto a=hex(at);if(!cmd("bph "+a+",x,1"))return false;
  nativeHardware.push_back(at);
  const bool isGate=std::find(nativeGateSites.begin(),nativeGateSites.end(),at)!=nativeGateSites.end();
  if(!configureNativeBinding(bp_hardware,at,(isGate?"KZ_G64_":"KZ_N64_")+a,isGate?"kz32_hit 12":"")||!nativeOwnHardware(at)||
   !DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)||bp.slot>=4||(occupied&(1u<<bp.slot)))return false;
  occupied|=1u<<bp.slot;
 }
 // While CS=33, the debugger's WOW64 context may not update the active native DRs.
 // Keep the execute guards until the actual native slots are installed and verified.
 KozWow64::Context installed;if(!KozWow64::get(eventThread,installed))return false;
 for(auto at:nativeHardware){
  BRIDGEBP bp{};if(!nativeOwnHardware(at)||!DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)||bp.slot>=4)return false;
  installed.q(72+8*bp.slot,at);
  installed.q(112,(installed.q(112)&~((3ull<<(2*bp.slot))|(15ull<<(16+4*bp.slot))))|(1ull<<(2*bp.slot)));
 }
 if(!KozWow64::setDebug(eventThread,installed)||!KozWow64::get(eventThread,installed))return false;
 for(auto at:nativeHardware){BRIDGEBP bp{};
  if(!DbgFunctions()->GetBridgeBp(bp_hardware,at,&bp)||bp.slot>=4||installed.q(72+8*bp.slot)!=at||!((installed.q(112)>>(2*bp.slot))&3))return false;
 }
 // Hardware now covers every syscall candidate on this page. Keeping an
 // execute guard here would single-step unrelated VM handlers as well.
 if(gate){
  BRIDGEBP bp{};if(DbgFunctions()->GetBridgeBp(bp_memory,page,&bp)&&
   (!nativeOwnGateGuard(page)||!removeNativeMemory(page)))return false;
 }
 for(auto it=nativeGuards.begin();it!=nativeGuards.end();){
  if(*it/system.dwPageSize!=page/system.dwPageSize){++it;continue;}
  if(!nativeOwnGuard(*it)||!removeNativeMemory(*it))return false;
  it=nativeGuards.erase(it);
 }
 nativeHardwarePage=page;return true;
}
static bool ensureNativeCoverage(duint ip,HANDLE thread){
 if(nativeMemoryFallback)return armNativeGuards(true);
 if(armNativeHardwarePage(ip,thread))return true;
 // Acceleration is optional. Do not leave a half-transferred page uncovered,
 // or auto-resume merely because its hardware allocation failed.
 nativeHardwarePage=0;
 if(!armNativeGuards(true)){
  log("Native coverage recovery failed at %08X; cannot restore all memory bindings",ip);return false;
 }
 for(auto at:nativeSites)if(!nativeOwnGuard(at)&&!nativeOwnGateGuard(at))return false;
 nativeMemoryFallback=true;
 log("Native hardware transfer unavailable at %08X; all %u syscall sites retain verified memory coverage",ip,static_cast<unsigned>(nativeSites.size()));
 return true;
}
static bool retireNativeGateBreakpoints(){
 BPMAP map{};DbgGetBpList(bp_normal,&map);bool ok=true;
 for(int i=0;i<map.count;i++){
  const auto& bp=map.bp[i];
  if(strncmp(bp.name,"KZ32_",5)||strcmp(bp.commandText,"kz32_hit 11"))continue;
  if(strcmp(bp.breakCondition,"0")||strcmp(bp.commandCondition,"1")||bp.fastResume||!bp.silent){
   log("Legacy gate breakpoint %08X was edited; left unchanged",bp.addr);ok=false;continue;
  }
  if(!cmd("bc "+hex(bp.addr)))ok=false;
 }
 if(map.bp)BridgeFree(map.bp);return ok;
}
static bool retireNativeBindings(){
 bool ok=true;
 for(auto type:{bp_memory,bp_hardware}){
  BPMAP map{};DbgGetBpList(type,&map);
  for(int i=0;i<map.count;i++){
   const auto& bp=map.bp[i];const bool memory=type==bp_memory;
   const bool gate=!strncmp(bp.name,memory?"KZ_G32_":"KZ_G64_",7);
   const bool returning=!memory&&!strncmp(bp.name,"KZ_R32_",7);
   if(!gate&&!returning&&strncmp(bp.name,memory?"KZ_N32_":"KZ_N64_",7))continue;
   const bool unchanged=memory?(gate?(nativeBindingSettings(bp,12)||nativeBindingSettings(bp,13)):
    (nativeBindingSettings(bp,10)||nativeBindingSettings(bp,14))):nativeBindingSettings(bp,returning?17:(gate?12:0));
   if(!unchanged){log("An old native binding was edited at %08X; retained",bp.addr);ok=false;continue;}
   if(memory){if(!removeNativeMemory(bp.addr))ok=false;}
   else{
    if(std::find(nativeHardware.begin(),nativeHardware.end(),bp.addr)==nativeHardware.end())nativeHardware.push_back(bp.addr);
   }
  }
  if(map.bp)BridgeFree(map.bp);
 }
 return clearNativeHardware(DbgGetThreadHandle())&&ok;
}
static bool installNativeSites(duint base,const IMAGE_NT_HEADERS32& nt){
 if(!retireNativeBindings())return false;
 nativeHardware.clear();nativeGuards.clear();nativeHardwarePage=0;nativeCoverageFault=false;nativeMemoryFallback=false;
 nativeGateSites.clear();nativeWindow=false;nativeHotGate=0;
 nativeGuardThread=0;nativeGuardIp=0;nativeGuardCode=0;nativeHardwareStepThread=0;
 if(!KozWow64::ssn("NtQueryInformationProcess",nativeQuery)||!KozWow64::ssn("NtSetInformationThread",nativeThread)||
  !KozWow64::ssn("NtSetInformationProcess",nativeProcess)||!KozWow64::ssn("NtQuerySystemInformation",nativeSystem)||!KozWow64::ssn("NtClose",nativeClose))return false;
 IMAGE_DOS_HEADER dos{};if(!read(base,dos)||nt.FileHeader.NumberOfSections>96)return false;
 const duint table=base+dos.e_lfanew+24+nt.FileHeader.SizeOfOptionalHeader;
 for(unsigned n=0;n<nt.FileHeader.NumberOfSections;n++){
  IMAGE_SECTION_HEADER s{};if(!read(table+n*sizeof(s),s))return false;
  if(!(s.Characteristics&IMAGE_SCN_MEM_EXECUTE)||!s.Misc.VirtualSize)continue;
  if(s.VirtualAddress>=nt.OptionalHeader.SizeOfImage||s.Misc.VirtualSize>nt.OptionalHeader.SizeOfImage-s.VirtualAddress)return false;
  constexpr size_t chunk=1024*1024;std::vector<unsigned char> bytes(chunk+8);
  for(size_t off=0;off<s.Misc.VirtualSize;off+=chunk){
   const size_t count=(std::min)(chunk+8,static_cast<size_t>(s.Misc.VirtualSize)-off);
   if(!DbgMemRead(base+s.VirtualAddress+static_cast<duint>(off),bytes.data(),count))return false;
   for(size_t i=0;i+7<=count&&i<chunk;i++){
    if(gateProfile()&&bytes[i]==0xea&&bytes[i+5]==0x33&&bytes[i+6]==0){
     uint32_t target=0;memcpy(&target,bytes.data()+i+1,4);
     if(target>=base&&target-base<nt.OptionalHeader.SizeOfImage)nativeGateSites.push_back(base+s.VirtualAddress+static_cast<duint>(off+i));
    }
    if(bytes[i]!=0x0f||bytes[i+1]!=0x05)continue;
    const auto t=bytes.data()+i+2;const duint at=base+s.VirtualAddress+static_cast<duint>(off+i);
    bool valid=(t[0]>=0x50&&t[0]<=0x57)||t[0]==0x68||t[0]==0x6a||t[0]==0x9c||(t[0]==0x41&&t[1]>=0x50&&t[1]<=0x57);
    if(t[0]==0xe8){int32_t delta=0;memcpy(&delta,t+1,4);const int64_t target=static_cast<int64_t>(at)+7+delta;valid=target>=base&&target<static_cast<int64_t>(base)+nt.OptionalHeader.SizeOfImage;}
    if(valid){if(nativeSites.size()>=4096)return false;nativeSites.push_back(at);}
   }
  }
 }
 if(!retireNativeGateBreakpoints()||(gateProfile()?!armNativeGates():!armNativeGuards()))return false;
 nativePhase=true;
 log("WOW64 native syscall bindings: %u",static_cast<unsigned>(nativeSites.size()));return !nativeSites.empty();
}
static bool endNativeWindow(duint ip){
 if(!clearNativeSites(false)||!refreshNativeGates())return false;
 nativeWindow=false;
 log("Returned to x32 at %08X; native memory guards released",ip);
 return true;
}
static bool handleNative(HANDLE eventThread=nullptr,bool* completed=nullptr){
 if(completed)*completed=false;
 KozWow64::Context c;const HANDLE thread=eventThread?eventThread:DbgGetThreadHandle();
 if(!thread||!KozWow64::get(thread,c)){log("Cannot read native WOW64 thread context");return false;}
 if((c.d(56)&0xffff)!=0x33)return true;
 uint64_t ip=c.q(248);auto found=std::find(nativeSites.begin(),nativeSites.end(),static_cast<duint>(ip));
 if(found==nativeSites.end()&&ip)found=std::find(nativeSites.begin(),nativeSites.end(),static_cast<duint>(ip-1));
 if(found==nativeSites.end()||ip>UINT32_MAX)return true;
 ip=*found;const auto service=static_cast<uint32_t>(c.q(120));const uint64_t a=c.q(200),b=c.q(136),buffer=c.q(184),size=c.q(192);
 uint32_t status=0;bool handled=false;
 log("Native syscall %X at %llX args=%llX,%llX,%llX,%llX",service,ip,a,b,buffer,size);
 uint64_t invalidLength=0;
 const bool malformedObject=service==nativeQuery&&b==0x1e&&on(2)&&
  (a==UINT64_MAX||a==0)&&(size==8||size==0)&&c.q(152)<=UINT32_MAX-0x30&&
  read(static_cast<duint>(c.q(152)+0x28),invalidLength)&&invalidLength==1;
 if(malformedObject){status=0xc0000005;handled=true;}
 else if(service==nativeQuery&&((b==7&&on(1))||((b==0x1e||b==0x1f)&&on(2)))&&(a==UINT64_MAX||(a<=UINT32_MAX&&self(static_cast<duint>(a))))&&(b==7||b==0x1e||b==0x1f)){
  const uint32_t length=b==0x1f?4:8;uint64_t retLength=0;
  if(size!=length||buffer>UINT32_MAX||(buffer&3)||!writable(static_cast<duint>(buffer),length)||c.q(152)>UINT32_MAX-0x30||!read(static_cast<duint>(c.q(152)+0x28),retLength))return false;
  if(retLength==1){status=0xc0000005;handled=true;}
  else{
   if(retLength&&(retLength>UINT32_MAX||(retLength&3)||!writable(static_cast<duint>(retLength),4)))return true;
   const uint64_t value=b==0x1f?1:0;if(!DbgMemWrite(static_cast<duint>(buffer),&value,length)||(retLength&&!write(static_cast<duint>(retLength),length)))return false;
   status=b==0x1e?0xc0000353:0;handled=true;
  }
 }else if(service==nativeThread&&on(3)&&b==0x11&&!buffer&&!size&&(a==UINT64_MAX-1||(a<=UINT32_MAX&&self(static_cast<duint>(a),true))))handled=true;
 else if(service==nativeProcess&&on(8)&&a==UINT64_MAX&&b==0x28&&size==16&&buffer<=UINT32_MAX){
  std::array<uint64_t,2> data{};handled=read(static_cast<duint>(buffer),data)&&data==std::array<uint64_t,2>{};
 }else if(service==nativeClose&&on(6)&&a==0xdeadc0de){handled=true;status=0xc0000008;}
 else if(service==nativeSystem&&(a==0x23||a==0xb)&&b<=UINT32_MAX&&buffer<=4*1024*1024&&size<=UINT32_MAX){
  const auto length=static_cast<uint32_t>(buffer);const auto output=static_cast<duint>(b);const auto returned=static_cast<duint>(size);
  if((length&&!writable(output,length))||(returned&&!writable(returned,4)))return false;
  std::vector<unsigned char> data((std::max)(length,1u));uint32_t used=0;
  static const auto query=KozWow64::resolve("NtQuerySystemInformation");if(!query)return false;
  status=static_cast<uint32_t>(KozWow64::call4(query,a,length?reinterpret_cast<uintptr_t>(data.data()):0,length,reinterpret_cast<uintptr_t>(&used)));
  if(static_cast<int32_t>(status)>=0){
   if(a==0x23&&on(4)&&length>=2){data[0]=0;data[1]=1;}
   if(a==0xb&&on(5)&&length>=8){
    uint32_t count=0;memcpy(&count,data.data(),4);if(count>(length-8)/0x128)return false;uint32_t kept=0;
    for(uint32_t i=0;i<count;i++){
     auto entry=data.data()+8+i*0x128;uint16_t offset=0;memcpy(&offset,entry+0x26,2);bool hide=false;
     if(offset<256&&memchr(entry+0x28+offset,0,256-offset))for(auto name:{"sice.sys","siwvid.sys","ntice.sys","iceext.sys","syser.sys"})if(!_stricmp(reinterpret_cast<const char*>(entry+0x28+offset),name))hide=true;
     if(!hide){memmove(data.data()+8+kept*0x128,entry,0x128);++kept;}
    }
    memset(data.data()+8+kept*0x128,0,(count-kept)*0x128);memcpy(data.data(),&kept,4);
   }
   if(length&&!DbgMemWrite(output,data.data(),(std::min)(used,length)))return false;
  }
  if(returned&&!write(returned,used))return false;handled=true;
 }
 if(!handled){
  // This shared wrapper also executes ordinary system calls. Let the real
  // instruction run once without retriggering its execute breakpoint.
  c.d(68,c.d(68)|0x10000u);
  return KozWow64::set(thread,c);
 }
 c.q(120,status);c.q(128,ip+2);c.q(208,c.d(68));c.q(248,ip+2);
 log("Native handled: service=%X class=%llX status=%08X",service,b,status);
 const bool applied=KozWow64::set(thread,c);
 if(service==nativeQuery&&buffer<=UINT32_MAX)nativeLastQueryBuffer=static_cast<duint>(buffer);
 KozWow64::Context verify;
 if(applied&&KozWow64::get(thread,verify))log("Native context readback: RIP=%llX RAX=%llX RSP=%llX flags=%X",verify.q(248),verify.q(120),verify.q(152),verify.d(68));
 if(completed)*completed=applied;return applied;
}


static bool clearNativeSites(bool hardware){
 GuiDisableUpdateScope updates(false);
 bool ok=!hardware||clearNativeHardware();
 for(auto it=nativeGuards.begin();it!=nativeGuards.end();){
  BRIDGEBP current{};
  if(!DbgFunctions()->GetBridgeBp(bp_memory,*it,&current)){it=nativeGuards.erase(it);continue;}
  if(!nativeOwnGuard(*it)||!removeNativeMemory(*it)){ok=false;++it;continue;}
  it=nativeGuards.erase(it);
 }
 return ok;
}
