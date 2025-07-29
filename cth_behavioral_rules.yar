// Behavior based rules for malware TTPS
// TODO: Customization as per user request. Currently all rules are included with --include-behavioral-rules

private rule reflective_DLL_injection {
    meta:
        description = "Detects instances of reflective DLL injectoin based on combination of technieques"
        author = "Amol Sarwate"
        version = "1.0"
    strings:
        $alloc1 = "VirtualAlloc" ascii wide
        $alloc2 = "VirtualProtect" ascii wide
        $thread1 = "CreateRemoteThread" ascii wide
        $ntalloc = "NtAllocateVirtualMemory" ascii wide
        $ntprotect = "NtProtectVirtualMemory" ascii wide
        $reflective_loader = "ReflectiveLoader" ascii wide
        $dll_entry = "DllMain" ascii wide
        $ntflush = "NtFlushInstructionCache" ascii wide
    condition:
        (uint16(0) == 0x5A4D) and
        (2 of ($alloc*) and 1 of ($thread*)) or (2 of ($ntalloc, $ntprotect)) or ($reflective_loader and $dll_entry and $ntflush)
}

private rule packed_with_upx {
    meta:
        description = "Detects PE files that are packed with UPX"
        author = "Amol Sarwate"
        version = "1.0"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX2" ascii
    condition:
        uint16(0) == 0x5A4D and any of ($upx*)
}

private rule DLL_side_loading {
    strings:
        $common_dll1 = "version.dll" ascii wide
        $common_dll2 = "msvcp140.dll" ascii wide
        $common_dll3 = "ntdll.dll" ascii wide
        $common_dll4 = "ws2_32.dll" ascii wide
        $load1 = "LoadLibraryA" ascii wide
        $load2 = "LoadLibraryW" ascii wide
        $load3 = "LoadLibraryExA" ascii wide
        $load4 = "LoadLibraryExW" ascii wide
        $system_directory = "\\\\Windows\\\\System32\\\\" ascii wide
    condition:
        (uint16(0) == 0x5A4D) and
        (1 of ($common_dll*)) and (1 of ($load*)) and not ($system_directory)
}

private rule kernel_hooking {
    strings:
        $ssdt_hook = { 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0 }
        $ntoskrnl = "ntoskrnl.exe" ascii wide
        $zw_functions = "ZwQuerySystemInformation" ascii wide
        $irp_hook = { 48 8B 05 ?? ?? ?? ?? 48 89 ?? ?? ?? ?? }
    condition:
        (uint16(0) == 0x5A4D) and
        (any of ($ssdt_hook, $irp_hook) and $ntoskrnl and $zw_functions)
}

private rule userMode_hooking {
    strings:
        $iat_hook = { FF 25 ?? ?? ?? ?? }
        $set_windows_hook = "SetWindowsHookEx" ascii wide
        $create_remote_thread = "CreateRemoteThread" ascii wide
        $load_library = "LoadLibraryA" ascii wide
    condition:
        (uint16(0) == 0x5A4D) and
        (any of ($iat_hook) or all of ($set_windows_hook, $create_remote_thread, $load_library))
}

