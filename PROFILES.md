# KozDbg profiles

## x64 profiles

x64 profiles are stored in `KozDbg.dp64.ini.profiles.ini`, next to the installed plugin. Open the file from **Settings > Profiles INI**.

On first launch, KozDbg creates the seven presets and migrates the existing checkbox settings. Existing profile files are preserved.

## Adding a profile

Copy an existing section and give it a unique ID. Letters, digits, underscores and hyphens are accepted; `off` is reserved for disabling the plugin.

Change the name and options, then restart x64dbg. Your profile will appear in both the Plugins menu and the settings dropdown.

```ini
[MyProfile]
Name=My custom profile
Engine=Api
Extended=0
Peb=1
RemoteDebugger=1
DebugObject=1
ThreadHiding=1
KernelDebugger=1
DriverNames=1
InvalidHandles=1
TrapFlag=1
Instrumentation=0
DebugRegisters=1
AttachProtection=0
TitanHideDevice=0
DecoderAcceleration=0
```

Use `0` to disable an option and `1` to enable it. Missing option keys default to `1`. Controls unsupported by the selected engine remain disabled in the GUI.

## Engines

| Preset | Engine | Extended |
|---|---|---|
| 331 / 340 / 350 | Api | 0 |
| 360 | ClusteredSyscalls | 0 |
| 380 | ScatteredSyscalls | 0 |
| 394 / 3101 | ScatteredSyscalls | 1 |

`Engine` selects an existing implementation. `Extended` enables the later checks.

Creating an INI profile does not add new detection handling. The implementation lives in `plugin.cpp` and the `.inl` files; new techniques require code changes and a rebuild.

## Saving and selecting

**Save & apply** writes the selected profile's checkboxes. Switching profiles discards unsaved checkbox edits. **Auto-enable** is shared across profiles.

You can also select a custom profile from the command bar:

```text
kz_profile MyProfile
```

Profile definitions remain fixed during the current debugging session. Restart x64dbg after adding profiles or changing engine settings.

The loader skips unknown engines and invalid IDs, accepts up to 128 profiles, and uses the built-in presets if no valid sections are found.

## x32 profiles

The x32 build stores its settings in `KozDbg.dp32.ini`. It does not read the x64 INI files or the x64 profile-definition file.

The built-in profile IDs are `331`, `340`, `350`, `360`, `380`, `394` and `3101`. Each appears separately in the menu and Settings. Custom named profiles and the `Engine` setting described above apply only to x64.

```ini
[Settings]
Enabled=1
AutoArm=1
Profile=3101

[Profile.3101]
Controls=4095
AttachProtection=1
```

`Controls` is a decimal bitmask. Using the checkboxes and **Save & apply** is the easiest way to edit it. `AttachProtection` stores the attach option separately and overrides bit 10 when loading the profile.

| Bit | Control |
|---|---|
| 0 | PEB / debugger flag |
| 1 | Remote debugger |
| 2 | Debug object |
| 3 | Thread hiding |
| 4 | Kernel debugger |
| 5 | Driver names |
| 6 | Invalid handles |
| 7 | Trap flag |
| 8 | Instrumentation |
| 9 | Debug registers |
| 10 | Attach protection |
| 11 | TitanHide device - profiles 394 and 3101 |

Decoder acceleration is not an x32 checkbox feature. The WOW64 transition handling is selected by the version profile. Disabled GUI controls are unavailable for the selected profile.

Use `kz_profile 3101` to select a version, `kz_profile off` to disable it, and `kz_status` to inspect its state. Keep this INI when replacing the `.dp32` file.

## Contact

Ivan Kozlovsky  
[ivankozlovsky.com](https://ivankozlovsky.com)  
[contact@ivankozlovsky.com](mailto:contact@ivankozlovsky.com)  
[PGP public key](https://ivankozlovsky.com/pgp.asc)

[MIT license](LICENSE)
