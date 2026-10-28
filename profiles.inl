// Profile storage is immutable after startup; engine callbacks retain stable pointers.
static constexpr std::array<const wchar_t*,13> optionKeys{{
 L"Peb",L"RemoteDebugger",L"DebugObject",L"ThreadHiding",L"KernelDebugger",
 L"DriverNames",L"InvalidHandles",L"TrapFlag",L"Instrumentation",L"DebugRegisters",
 L"AttachProtection",L"TitanHideDevice",L"DecoderAcceleration"
}};
struct ProfileText {std::string key,name;std::wstring label;};
static std::deque<ProfileText> profileText;
static std::wstring widen(const char* text){std::wstring out;while(*text)out+=static_cast<unsigned char>(*text++);return out;}
static unsigned readProfileOptions(unsigned index){
 const auto section=widen(profiles[index].key);unsigned value=0;
 for(unsigned i=0;i<controlCount;i++)if(GetPrivateProfileIntW(section.c_str(),optionKeys[i],1,profilesPath.c_str()))value|=1u<<i;
 return value;
}
static void saveProfileOptions(){
 const auto section=widen(profile().key);
 for(unsigned i=0;i<controlCount;i++)WritePrivateProfileStringW(section.c_str(),optionKeys[i],on(i)?L"1":L"0",profilesPath.c_str());
}
static void loadProfiles(){
 // First startup migrates the old checkbox mask into each preset, without overwriting existing files.
 if(GetFileAttributesW(profilesPath.c_str())==INVALID_FILE_ATTRIBUTES){
  for(const auto& p:profiles){
   const auto section=widen(p.key);
   WritePrivateProfileStringW(section.c_str(),L"Name",p.label,profilesPath.c_str());
   const wchar_t* engine=p.engine==Engine::Api?L"Api":p.engine==Engine::ClusteredSyscalls?L"ClusteredSyscalls":L"ScatteredSyscalls";
   WritePrivateProfileStringW(section.c_str(),L"Engine",engine,profilesPath.c_str());
   WritePrivateProfileStringW(section.c_str(),L"Extended",p.extended?L"1":L"0",profilesPath.c_str());
   for(unsigned i=0;i<controlCount;i++)WritePrivateProfileStringW(section.c_str(),optionKeys[i],on(i)?L"1":L"0",profilesPath.c_str());
  }
 }
 std::vector<wchar_t> sections(32768);
 const DWORD length=GetPrivateProfileSectionNamesW(sections.data(),static_cast<DWORD>(sections.size()),profilesPath.c_str());
 if(length>=sections.size()-2){log("Profiles INI is too large; using built-in defaults.");return;}
 std::vector<Profile> loaded;
 for(const wchar_t* section=sections.data();*section;section+=wcslen(section)+1){
  std::string key;bool valid=true;
  for(const wchar_t* c=section;*c;++c){if(!((*c>=L'a'&&*c<=L'z')||(*c>=L'A'&&*c<=L'Z')||(*c>=L'0'&&*c<=L'9')||*c==L'_'||*c==L'-')){valid=false;break;}key+=static_cast<char>(*c);}
  if(!valid||key.size()>64||_stricmp(key.c_str(),"off")==0){log("Skipping invalid profile ID; use letters, digits, underscore or hyphen, except off.");continue;}
  wchar_t engineName[64]{},label[256]{};
  GetPrivateProfileStringW(section,L"Engine",L"",engineName,64,profilesPath.c_str());
  Engine engine;
  if(wcscmp(engineName,L"Api")==0)engine=Engine::Api;
  else if(wcscmp(engineName,L"ClusteredSyscalls")==0)engine=Engine::ClusteredSyscalls;
  else if(wcscmp(engineName,L"ScatteredSyscalls")==0)engine=Engine::ScatteredSyscalls;
  else {log("Skipping profile with missing or unknown Engine.");continue;}
  GetPrivateProfileStringW(section,L"Name",section,label,256,profilesPath.c_str());
  char utf8[1024]{};WideCharToMultiByte(CP_UTF8,0,label,-1,utf8,1024,nullptr,nullptr);
  profileText.push_back({key,utf8,label});const auto& text=profileText.back();
  loaded.push_back({text.key.c_str(),text.key.c_str(),text.name.c_str(),text.label.c_str(),1000+static_cast<int>(loaded.size()),engine,GetPrivateProfileIntW(section,L"Extended",0,profilesPath.c_str())!=0});
  if(loaded.size()==128){log("Profile limit reached (128).");break;}
 }
 if(!loaded.empty())profiles=std::move(loaded);
 else log("No valid INI profiles; using built-in defaults.");
}
