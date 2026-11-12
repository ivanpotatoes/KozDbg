# KozDbg x32

An anti-anti-debug plugin for **x32dbg**, supporting the tested VMProtect versions from **3.3.1 to 3.10.1**.

**No kernel driver required**, including the 3.10.1 profile. Supported kernel-debugger queries are handled from user mode.

This branch contains the **x32 source and build configuration**. [main](https://github.com/ivanpotatoes/KozDbg/tree/main) contains both builds. The other build is on [x64](https://github.com/ivanpotatoes/KozDbg/tree/x64).

[Download v1.1.2](https://github.com/ivanpotatoes/KozDbg/releases/download/v1.1.2/KozDbg-v1.1.2-x32.zip) · [Profile format](PROFILES.md) · [Report a bug](https://github.com/ivanpotatoes/KozDbg/issues)

Settings shown from the x64 build; the x32 controls depend on the selected profile.

![KozDbg settings](media/screenshots/settings.png)

## Getting started

1. Close x32dbg and copy `KozDbg.dp32` into its `plugins` folder.
2. For a fresh installation, copy the included INI files there too. **When updating, keep your existing INI files and replace only the plugin.**
3. Open **Plugins > KozDbg x32** and select the VMProtect version.
4. Leave **Auto-enable** checked, load the program and look for `profile armed` in the log. Press **F9** to continue; press it again if the debugger stops at the entry breakpoint.

Settings are stored in `KozDbg.dp32.ini`. The default profile is 3.3.1. Select the right profile before running the target. If setup fails, check the log.

## Supported and tested versions

| VMProtect | Profile | x32 / x32dbg |
|---|---|---|
| 3.3.1 | `331` | Tested - passed |
| 3.4.0 | `340` | Tested - passed |
| 3.5.0 | `350` | Tested - passed |
| 3.6.0 | `360` | Tested - passed |
| 3.8.0 | `380` | Tested - passed |
| 3.9.4 | `394` | Tested - passed |
| 3.10.1 | `3101` | Tested - passed |

All seven listed versions were tested. These results cover our protected test programs, including samples with additional protection options; they do not guarantee every protected binary or intermediate VMProtect build.

## What it handles

- PEB debugger flags, remote debugger and debug object queries
- Thread hiding, kernel debugger queries and driver-name checks
- Invalid handles, trap-flag exceptions and saved debug registers
- Instrumentation callback clearing and remote-breakin protection
- TitanHide device checks in the later profiles

The x32 build runs under WOW64 on 64-bit Windows. It uses hardware breakpoints and memory guards to track native transitions and needs a free hardware slot for the return. Existing user breakpoints are retained. The v1.1.2 fix avoids memory growth during repeated hardware-slot queries, reproduced with the 3.8.0 sample.

Profiles are not tied to sample addresses. Startup time and compatibility depend on the protection settings and code layout. Unpacking, devirtualization, key checks and anti-VM checks are outside this plugin's scope.

## Profiles and commands

Select a profile from the menu or open Settings. Hover over **?** to see what a control does. Pause a running target before using **Save & apply**.

The seven built-in version profiles have separate option sections. Custom named profiles are available in the x64 build. See [PROFILES.md](PROFILES.md).

| Command | Action |
|---|---|
| `kz_settings` | Open Settings |
| `kz_profile 331` | Select VMProtect 3.3.1 |
| `kz_profile off` | Disable KozDbg |
| `kz_apply` | Apply the selected profile while paused |
| `kz_status` | Show state and counters |

## Build from source

Use Windows, Visual Studio 2022 with **Desktop development with C++**, CMake 3.20+ and the [x64dbg plugin SDK](https://github.com/x64dbg/x64dbg).

```powershell
git clone --branch x32 https://github.com/ivanpotatoes/KozDbg.git
cd KozDbg
cmake -S . -B ../KozDbg-build-x32 -A Win32 -DX64DBG_SDK="C:/path/to/pluginsdk"
cmake --build ../KozDbg-build-x32 --config Release
```

The SDK must contain `_plugins.h`, `x32dbg.lib` and `x32bridge.lib`. Output: `../KozDbg-build-x32/Release/KozDbg.dp32`.

For bug reports, include the debugger build, VMProtect version, protection options, profile and relevant KozDbg log.

## Demo

This video shows the **x64 build**. Three small programs, **BasicProbe**, **RiddleGame** and **KeyCheck**, are protected with different VMProtect versions and then run in x64dbg with KozDbg. Click the thumbnail to watch.

[![Watch the KozDbg demo](https://img.youtube.com/vi/r7Q8KtjtaA0/hqdefault.jpg)](https://www.youtube.com/watch?v=r7Q8KtjtaA0)

## Research behind KozDbg

- [VMProtect 3.3.x–3.5.x anti-debug analysis](https://ivankozlovsky.com/blog/vmprotect-33x-35x-anti-debug-analysis)
- [VMProtect 3.6 anti-debug analysis](https://ivankozlovsky.com/blog/vmprotect-36-anti-debug-analysis)
- [VMProtect 3.8.0 anti-debug analysis](https://ivankozlovsky.com/blog/vmprotect-380-anti-debug-analysis)
- [VMProtect 3.9.4 anti-debug analysis](https://ivankozlovsky.com/blog/vmprotect-394-anti-debug-analysis)
- [VMProtect 3.10.1 anti-debug analysis](https://ivankozlovsky.com/blog/vmprotect-3101-anti-debug-analysis)

## Author

**Ivan Kozlovsky** · [ivankozlovsky.com](https://ivankozlovsky.com) · [contact@ivankozlovsky.com](mailto:contact@ivankozlovsky.com) · [PGP](https://ivankozlovsky.com/pgp.asc)

Released under the [MIT license](LICENSE).

## Star history

[![KozDbg star history](https://api.star-history.com/svg?repos=ivanpotatoes/KozDbg&type=Date)](https://www.star-history.com/?repos=ivanpotatoes%2Fkozdbg&type=date&legend=top-left)
