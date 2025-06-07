# Go-win-process-injector

## Description
This program is highly configurable process injector made in Go that can run both in interactive mode or as a Windows Service.

This project was born when during my researches on process injections in Go. I needed to execute complex code made in Go with a DLL injection but Go does not incorporate logic similar to DllMain to allow direct execution once the code has been injected. This injector takes care of finding the address of the target function and then executing it in the context of the process where the injection took place.

## Compilation
* Install golang latest version [here](https://go.dev/)
* compile to exe with `go build -ldflags "-s -w" .`

## YAML Config File example
```
injector_log_level: "LOGLEVEL_INFO"                               # use LOGLEVEL_DEBUG for a verbose logging 
injector_log_file: "C:\\Windows\\Temp\\goprocinjector.log"        # let blank if you don't want to log in a file                           
process_injections:                                               # add your DLL injection as a list like in this example
- name: "ClipboardMonitor_WebBrowser"
    processes: 
    - "firefox.exe"
    - "chrome.exe"
    process_injection_dll_path: "C:\\Users\\shado\\Desktop\\clipboardMonitor\\ClipboardMonitor.dll"
    process_injection_dll_function: "ClipboardMonitor"
    process_injection_refresh_interval: 5
- name: "ClipboardMonitor_Explorer"
    processes: 
    - "explorer.exe"
    process_injection_dll_path: "C:\\Users\\shado\\Desktop\\clipboardMonitor\\ClipboardMonitor.dll"
    process_injection_dll_function: "ClipboardMonitor"
    process_injection_refresh_interval: 30
```

## Execution
* Just launch executable with `goprocinjector.exe -c "C:\\Path\\To\\Your\\goprocinjector.yaml"`
* You can also register it as a windows service with `sc create` if your want a permanent execution at Windows startup 

## Injection code details

Quick and easy way:
* Use injectInProcess() to inject in the specified PID and call any selected function inside the memory space of this process
* Use GetInjectedLibraryModuleHandle() to check if your library already is injected to avoid multiple useless injection

If you want more details on how it works:
* It first OpenProcess() your target PID
* Then, injectDLL() create a remote thread an load your DLL inside it
* findSymbolRVA() identify the relative virtual address of your function in the dll
* Finally, callRemoteFunction() execute it in a new thread of your target PID

## Process output:
```
[INFO] Starting process injection...
[INFO] Found process: Notepad.exe (PID: 17472)
[DEBUG] PID: 17472 - Opening process Notepad.exe with 0x2a access...
[DEBUG] PID: 17472 - Process Handle: 0x228
[DEBUG] Loading DLL: C:\Temp\MyDll.dll
[DEBUG] PID: 17472 - DLL Path Length: 40
[INFO] PID: 17472 - VirtualAllocEx...
[DEBUG] PID: 17472 - Allocating memory at:  0x21a60370000
[DEBUG] PID: 17472 - Bytes written: 82
[DEBUG] PID: 17472 - CreateRemoteThread...
[DEBUG] PID: 17472 - Thread Handle: 556
[DEBUG] PID: 17472 - Waiting for thread to finish...
[DEBUG] PID: 17472 - DLL address in the remote process: 0x7ffe1eab0000
[INFO] PID: 17472 - DLL injected successfully.
[DEBUG] PID: 17472 - Function 'MyInjectFunction' RVA: 0xb2e60
[INFO] PID: 17472 - Function 'MyInjectFunction' successfully called.
```