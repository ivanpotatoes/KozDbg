// The x86 VM places the service descriptor and DWORD arguments on its own
// stack. The WOW64 marshaller replaces the last argument with NTSTATUS.
// Observe this boundary rather than every possible native syscall instruction.
struct GateCall {
 DWORD thread=0,hiddenThread=0;duint ret=0,stack=0,frame=0,descriptor=0;
 unsigned count=0,kind=0;std::array<duint,6> args{};bool changedHandle=false;
 duint nameLengthAddress=0;uint16_t nameLength=0;
};
static GateCall gateCall;
static uint32_t gateQuery=0,gateThread=0,gateProcess=0;
static uint32_t gateQueryThread=0,gateSystem=0,gateOpen=0,gateObject=0,gateCreateObject=0;
static std::vector<DWORD> gateHiddenThreads;
static bool gatePortSeen=false,gateObjectSeen=false,gateHideSeen=false;
static bool gateFinished=false;
static bool gateRestoreUserHardware(){
 // Native/WOW64 context switches can leave the engine's enabled user binding
 // absent from the live DRs. Reapply only those slots, retaining all settings.
 BPMAP map{};DbgGetBpList(bp_hardware,&map);
 KozWow64::Context native;CONTEXT wow{};wow.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 bool loaded=false,changed=false,ok=true;DWORD* regs[]={&wow.Dr0,&wow.Dr1,&wow.Dr2,&wow.Dr3};
 for(int i=0;i<map.count;i++){
  const auto& bp=map.bp[i];if(!bp.enabled||!bp.active||bp.slot>=4||nativeOwnHardware(bp.addr))continue;
  if(!loaded){if(!KozWow64::get(DbgGetThreadHandle(),native)||!GetThreadContext(DbgGetThreadHandle(),&wow)){ok=false;break;}loaded=true;}
  if(bp.typeEx>hw_execute||bp.hwSize>hw_qword){ok=false;break;}
  const unsigned slot=bp.slot;const uint64_t rw=bp.typeEx==hw_execute?0:(bp.typeEx==hw_write?1:3);
  constexpr unsigned lengths[]={0,1,3,2};const uint64_t len=rw?lengths[bp.hwSize]:0;
  const uint64_t mask=(3ull<<(2*slot))|(15ull<<(16+4*slot));
  const uint64_t flags=(1ull<<(2*slot))|((rw|(len<<2))<<(16+4*slot));
  if(native.q(72+8*slot)!=bp.addr||(native.q(112)&mask)!=flags||*regs[slot]!=bp.addr||(wow.Dr7&mask)!=flags){
   native.q(72+8*slot,bp.addr);native.q(112,(native.q(112)&~mask)|flags);
   *regs[slot]=bp.addr;wow.Dr7=(wow.Dr7&~static_cast<DWORD>(mask))|static_cast<DWORD>(flags);changed=true;
  }
 }
 if(map.bp)BridgeFree(map.bp);
 if(ok&&changed){ok=SetThreadContext(DbgGetThreadHandle(),&wow)&&KozWow64::setDebug(DbgGetThreadHandle(),native);if(ok)log("User hardware bindings restored across WOW64 transition; settings retained");}
 return ok;
}
static DWORD gateThreadId(duint handle){
 if(handle==duint(-2))return DbgGetThreadId();
 HANDLE copy=nullptr;
 if(!DuplicateHandle(DbgGetProcessHandle(),reinterpret_cast<HANDLE>(handle),GetCurrentProcess(),&copy,0,FALSE,DUPLICATE_SAME_ACCESS))return 0;
 const DWORD id=GetProcessIdOfThread(copy)==GetProcessId(DbgGetProcessHandle())?GetThreadId(copy):0;
 CloseHandle(copy);return id;
}
static bool gateCleanup(){
 if(!gateCall.thread)return true;
 bool ok=true;
 if(gateCall.changedHandle)ok=write(gateCall.frame+4,gateCall.args[0])&&ok;
 if(gateCall.nameLengthAddress)ok=write(gateCall.nameLengthAddress,gateCall.nameLength)&&ok;
 if(ok)gateCall={};return ok;
}
static bool gateTitanName(duint output,duint attributes,duint iosb,duint& lengthAddress,uint16_t& length){
 struct Attributes {uint32_t length,root,name,flags,security,sqos;};
 struct String {uint16_t length,maximum;uint32_t buffer;};
 Attributes a{};String s{};constexpr wchar_t device[]=L"\\??\\TitanHide";
 if(!extendedChecks()||!on(11)||(output&3)||(iosb&3)||(attributes&3)||!writable(output,4)||!writable(iosb,8)||
  !read(attributes,a)||a.length!=sizeof(a)||a.root||a.security||a.sqos||(a.name&3)||!read(a.name,s)||
  s.length!=sizeof(device)-sizeof(wchar_t)||s.maximum<s.length)return false;
 std::array<wchar_t,std::size(device)> name{};if(!DbgMemRead(s.buffer,name.data(),s.length))return false;
 if((a.flags&0x40)?_wcsicmp(name.data(),device)!=0:wcscmp(name.data(),device)!=0)return false;
 lengthAddress=a.name;length=s.length;return true;
}
static bool gateSuspendPages(){
 for(const auto at:nativeGateSites){
  const auto page=nativePage(at);BRIDGEBP bp{};
  if(!DbgFunctions()->GetBridgeBp(bp_memory,page,&bp))continue;
  if(!nativeOwnGateGuard(page)||!removeNativeMemory(page))return false;
 }
 return true;
}
static bool gateDescriptor(const char* name,uint32_t& value){
 const auto stub=resolve(name,true);return stub>=5&&read(stub-4,value);
}
static bool gateInitialize(){
 gateCall={};gateFinished=false;gatePortSeen=gateObjectSeen=gateHideSeen=false;gateHiddenThreads.clear();
 return gateDescriptor("ntdll:NtQueryInformationProcess",gateQuery)&&
  gateDescriptor("ntdll:NtSetInformationThread",gateThread)&&
  gateDescriptor("ntdll:NtSetInformationProcess",gateProcess)&&
  gateDescriptor("ntdll:NtQueryInformationThread",gateQueryThread)&&
  gateDescriptor("ntdll:NtQuerySystemInformation",gateSystem)&&
  gateDescriptor("ntdll:NtOpenFile",gateOpen)&&
  gateDescriptor("ntdll:NtQueryObject",gateObject)&&
  gateDescriptor("ntdll:NtCreateDebugObject",gateCreateObject);
}
static bool gateBegin(duint ip,HANDLE thread){
 if(gateFinished)return true;
 if(gateCall.thread){log("Nested WOW64 transition; refusing to overwrite its return record");return false;}
 KozWow64::Context c;
 if(!KozWow64::get(thread,c)||(c.d(56)&0xffff)!=0x23||c.q(152)>UINT32_MAX-8)return false;
 GateCall next{};next.thread=DbgGetThreadId();next.stack=static_cast<duint>(c.q(152))+8;
 uint32_t cs=0;const auto sp=static_cast<duint>(c.q(152));
 if(!read(sp,next.ret)||!read(sp+4,cs)||cs!=0x23||
  Script::Module::BaseFromAddr(next.ret)!=Script::Module::GetMainModuleBase())return false;
 std::array<unsigned char,8> tail{};
 if(!DbgMemRead(next.ret,tail.data(),tail.size())||
  tail!=std::array<unsigned char,8>{0x90,0x66,0x8c,0xd1,0x66,0x8e,0xd1,0xe9}){
  log("Unrecognized WOW64 return sequence at %08X",next.ret);return false;
 }
 duint top=0,bottom=0;const auto teb=DbgGetTebAddress(next.thread);
 if(!read(teb+4,top)||!read(teb+8,bottom))return false;
 for(const size_t offset:{120u,128u,136u,144u,160u,168u,176u}){
  const auto value=c.q(offset);if(top<28||value<bottom||value>top-28||(value&3))continue;
  const auto frame=static_cast<duint>(value);uint32_t descriptor=0;if(!read(frame,descriptor))continue;
  unsigned count=0,kind=0;
  if((descriptor&0xff0000)!=0x10000)continue;
  const auto service=descriptor&0xffff;
  if(service==(gateQuery&0xffff)){count=5;kind=1;}
  else if(service==(gateThread&0xffff)){count=4;kind=2;}
  else if(service==(gateProcess&0xffff)){count=4;kind=3;}
  else if(service==(gateQueryThread&0xffff)){count=5;kind=4;}
  else if(service==(gateSystem&0xffff)){count=4;kind=5;}
  else if(service==(gateOpen&0xffff)){count=6;kind=6;}
  else if(service==(gateObject&0xffff)){count=5;kind=7;}
  else if(service==(gateCreateObject&0xffff)){count=4;kind=8;}
  else continue;
  std::array<duint,6> args{};
  if(!writable(frame,(count+1)*4)||!DbgMemRead(frame+4,args.data(),count*4))continue;
  // VM scratch registers can point at stale copies of the same descriptor.
  // Track only the information classes this observer understands; an unrelated
  // call still runs normally and retains the return-boundary guard restoration.
  if(kind==1&&args[1]!=7&&args[1]!=0x1e&&args[1]!=0x1f)continue;
  if((kind==2||kind==4)&&args[1]!=0x11)continue;
  if(kind==3&&args[1]!=0x28)continue;
  if(kind==5&&args[0]!=0x23)continue;
  if(kind==7&&args[1]!=2)continue;
  if(kind==6){duint nameAddress=0;uint16_t nameLength=0;if(!gateTitanName(args[0],args[2],args[3],nameAddress,nameLength))continue;}
  if(kind==8&&((args[0]&3)||!writable(args[0],4)))continue;
  if(next.frame&&next.frame!=frame){log("Ambiguous WOW64 argument frames at %08X",ip);return false;}
  next.args=args;next.frame=frame;next.count=count;next.kind=kind;next.descriptor=descriptor;
 }
 // A return slot is essential even for ordinary calls: restore gate coverage
 // only after the native VM has left its exception-sensitive transition.
 if(!clearNativeHardware(thread))return false;
 BRIDGEBP existing{};unsigned occupied=0;
 if(DbgFunctions()->GetBridgeBp(bp_hardware,next.ret,&existing)||!nativeOccupiedSlots(occupied)||occupied==15){
  log("No free hardware slot for WOW64 return; user breakpoints retained");return false;
 }
 if(!cmd("bph "+hex(next.ret)+",x,1"))return false;
 nativeHardware.push_back(next.ret);
 if(!configureNativeBinding(bp_hardware,next.ret,"KZ_R32_"+hex(next.ret),"kz32_hit 17")||!gateSuspendPages())return false;
 if(next.kind==2&&on(3)&&next.args[1]==0x11&&!next.args[2]&&!next.args[3]&&self(next.args[0],true)){
  next.hiddenThread=gateThreadId(next.args[0]);if(!next.hiddenThread)return false;
  if(!write(next.frame+4,uint32_t(0)))return false;next.changedHandle=true;
 }
 if(next.kind==6&&gateTitanName(next.args[0],next.args[2],next.args[3],next.nameLengthAddress,next.nameLength)){
  // An empty absolute name with no root cannot open a device. Let the real
  // marshaller run, then restore the caller's string and report not found.
  if(!writable(next.nameLengthAddress,2)||!write(next.nameLengthAddress,uint16_t(0)))return false;
 }
 gateCall=next;
 log("WOW64 call boundary %08X -> %08X frame=%08X descriptor=%08X",ip,next.ret,next.frame,next.descriptor);
 if(next.frame&&extendedChecks())log("WOW64 args kind=%u count=%u: %08X,%08X,%08X,%08X,%08X,%08X",next.kind,next.count,next.args[0],next.args[1],next.args[2],next.args[3],next.args[4],next.args[5]);
 return true;
}
static bool gateReturn(){
 const auto call=gateCall;if(!call.thread||call.thread!=DbgGetThreadId())return false;
 KozWow64::Context c;
 if(!KozWow64::get(DbgGetThreadHandle(),c)||c.q(248)!=call.ret||c.q(152)!=call.stack||(c.d(56)&0xffff)!=0x23)return false;
 uint32_t status=0;const auto slot=call.frame+call.count*4;
 if(call.frame){
  uint32_t descriptor=0;if(!read(call.frame,descriptor)||descriptor!=call.descriptor||!read(slot,status))return false;
  if(call.nameLengthAddress){
   if(!write(call.nameLengthAddress,call.nameLength)||!write(slot,uint32_t(0xc0000034)))return false;
   status=0xc0000034;++hits[11];log("WOW64 exact TitanHide open blocked; caller name restored");
  }else if(call.changedHandle){
   if(!write(call.frame+4,call.args[0])||!write(slot,uint32_t(0)))return false;
   gateHideSeen=true;++hits[3];status=0;
   if(std::find(gateHiddenThreads.begin(),gateHiddenThreads.end(),call.hiddenThread)==gateHiddenThreads.end())gateHiddenThreads.push_back(call.hiddenThread);
  }else if(call.kind==1&&self(call.args[0])&&static_cast<int32_t>(status)>=0){
   if(call.args[1]==7&&on(1)&&call.args[3]==4){
    if(!write(call.args[2],uint32_t(0)))return false;gatePortSeen=true;++hits[1];
   }else if(call.args[1]==0x1e&&on(2)&&call.args[3]==4){
    // The real marshaller has already performed ReturnLength validation and
    // its overlapping write. Preserve that write when both pointers alias.
    if(call.args[4]!=call.args[2]&&!write(call.args[2],uint32_t(0)))return false;
    if(!write(slot,uint32_t(0xc0000353)))return false;status=0xc0000353;gateObjectSeen=true;++hits[2];
   }else if(call.args[1]==0x1f&&on(2)&&call.args[3]==4){
    if(!write(call.args[2],uint32_t(1)))return false;++hits[2];
   }
  }else if(call.kind==4&&extendedChecks()&&on(3)&&call.args[1]==0x11&&call.args[3]==1&&self(call.args[0],true)&&static_cast<int32_t>(status)>=0&&
   std::find(gateHiddenThreads.begin(),gateHiddenThreads.end(),gateThreadId(call.args[0]))!=gateHiddenThreads.end()){
   if(!write(call.args[2],static_cast<unsigned char>(1)))return false;++hits[3];
   log("WOW64 thread-hide query reports the previously suppressed hide");
  }else if(call.kind==5&&on(4)&&call.args[0]==0x23&&call.args[2]>=2&&static_cast<int32_t>(status)>=0){
   if(!write(call.args[1],uint16_t(0x100)))return false;++hits[4];
  }
 }
 log("WOW64 return frame=%08X status=%08X",call.frame,status);
 gateCall={};
 return clearNativeHardware(DbgGetThreadHandle())&&armNativeGates()&&gateRestoreUserHardware();
}
static bool gateFinishStartup(){
 if(!gateProfile()||gateFinished||!gatePortSeen||!gateObjectSeen||!gateHideSeen)return true;
 if(gateCall.thread||!gateSuspendPages()||!clearNativeHardware(DbgGetThreadHandle())||!gateRestoreUserHardware())return false;
 // The loader has reached its invalid-handle/TF probes. Keeping BeingDebugged
 // hidden here changes exception routing, unlike the earlier direct PEB check.
 if(pebFlag&&!write(pebFlag,savedPeb))return false;
 if(nativePebFlag&&!KozWow64::writeTarget(DbgGetProcessHandle(),nativePebFlag,&savedNativePeb,1))return false;
 // With the original PEB flags restored the break-in branch needs no override.
 for(auto it=owned.begin();it!=owned.end();){
  if(it->action!=16){++it;continue;}
  if(!removeBinding(*it))return false;it=owned.erase(it);
 }
 gateFinished=true;nativePhase=false;nativeHardwareStepThread=0;
 log("WOW64 startup checks completed; PEB restored for exception delivery, loader guards released");
 return true;
}
