# Go-win-process-injector

## Description
During my researches on process injection in Go, i have only found shellcode injections. But, in my case, I needed to include complex code in the process i was injecting into without instability linked to my action.

This complex code was compiled in a Go DLL. However, Go does not incorporate logic similar to DllMain to allow direct execution of a function once the code has been injected. This program therefore takes care of finding the address of the target function and then executing it in the context of the process where the injection took place. 

## Instruction, example and sequence of the injection

Quick and easy way:
* Use injectInProcess() to inject in the specified PID and call any selected function inside the memory space of this process
* Use GetInjectedLibraryModuleHandle() to check if your library already is injected to avoid multiple useless injection

If you want more details on how it works:
* It first OpenProcess() your target PID
* Then, injectDLL() create a remote thread an load your DLL inside it
* findSymbolRVA() identify the relative virtual address of your function in the dll
* Finally, callRemoteFunction() execute it in a new thread of your target PID

Process output:
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