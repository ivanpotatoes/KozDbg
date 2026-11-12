# KozDbg x32 profiles

The x32 build stores its settings in `KozDbg.dp32.ini`. It does not read the x64 INI files or the x64 profile-definition file.

The built-in profile IDs are `331`, `340`, `350`, `360`, `380`, `394` and `3101`. Each appears separately in the menu and Settings. Custom named profiles and the `Engine` setting apply only to x64.

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
