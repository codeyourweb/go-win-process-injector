package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32DLL              = syscall.NewLazyDLL("kernel32.dll")
	loadLibraryW             = kernel32DLL.NewProc("LoadLibraryW")
	virtualAllocEx           = kernel32DLL.NewProc("VirtualAllocEx")
	virtualFreeEx            = kernel32DLL.NewProc("VirtualFreeEx")
	writeProcessMemory       = kernel32DLL.NewProc("WriteProcessMemory")
	createRemoteThread       = kernel32DLL.NewProc("CreateRemoteThread")
	getThreadId              = kernel32DLL.NewProc("GetThreadId")
	createToolhelp32Snapshot = kernel32DLL.NewProc("CreateToolhelp32Snapshot")
	process32FirstW          = kernel32DLL.NewProc("Process32FirstW")
	process32NextW           = kernel32DLL.NewProc("Process32NextW")
)

type PROCESSENTRY32 struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [syscall.MAX_PATH]uint8
}

const (
	MEM_RESERVE        = 0x00002000
	MEM_COMMIT         = 0x00001000
	TH32CS_SNAPPROCESS = 0x00000002
)

func injectDLL(processID uint32, processHandle windows.Handle, dllPath string) (uintptr, error) {
	dllPathPtr, err := windows.UTF16PtrFromString(dllPath)
	if err != nil {
		return 0, err
	}

	remoteAlloc, _, err := virtualAllocEx.Call(
		uintptr(processHandle),
		0,
		uintptr(len(dllPath)*2+2),
		uintptr(MEM_RESERVE|MEM_COMMIT),
		uintptr(windows.PAGE_READWRITE),
	)
	if remoteAlloc == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - VirtualAllocEx...", processID))
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Allocating memory at:  0x%x", processID, remoteAlloc))

	bytesWritten := uint(0)
	_, _, err = writeProcessMemory.Call(
		uintptr(processHandle),
		remoteAlloc,
		uintptr(unsafe.Pointer(dllPathPtr)),
		uintptr(len(dllPath)*2+2),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if bytesWritten == 0 {
		return 0, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Bytes written: %d", processID, bytesWritten))

	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - CreateRemoteThread...", processID))
	threadHandle, _, err := createRemoteThread.Call(
		uintptr(processHandle),
		0,
		0,
		uintptr(loadLibraryW.Addr()),
		remoteAlloc,
		0,
		0,
	)
	if threadHandle == 0 {
		return 0, fmt.Errorf("CreateRemoteThread failed: %v", err)
	}
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Thread Handle: %d", processID, threadHandle))
	defer syscall.CloseHandle(syscall.Handle(threadHandle))

	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Waiting for thread to finish...", processID))
	_, err = syscall.WaitForSingleObject(syscall.Handle(threadHandle), syscall.INFINITE)
	if err != nil {
		return 0, fmt.Errorf("WaitForSingleObject failed: %v", err)
	}

	remoteDLLHandle, err := GetInjectedLibraryModuleHandle(processID, dllPath)
	if err != nil {
		return 0, fmt.Errorf("GetModuleHandle failed: %v", err)
	}
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - DLL address in the remote process: 0x%x", processID, remoteDLLHandle))

	return remoteDLLHandle, nil
}

func GetInjectedLibraryModuleHandle(processID uint32, injectedDllPath string) (uintptr, error) {
	handle, err := syscall.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		return 0, fmt.Errorf("error opening process: %w", err)
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var modules [1024]windows.Handle
	var needed uint32
	err = windows.EnumProcessModules(windows.Handle(handle), &modules[0], uint32(unsafe.Sizeof(modules)), &needed)
	if err != nil {
		return 0, fmt.Errorf("error enumerating process modules: %v", err)
	}

	numModules := needed / uint32(unsafe.Sizeof(windows.Handle(0)))
	for i := uint32(0); i < numModules; i++ {
		var filename [windows.MAX_PATH]uint16
		err = windows.GetModuleFileNameEx(windows.Handle(handle), modules[i], &filename[0], windows.MAX_PATH)
		if err == nil && windows.UTF16ToString(filename[:]) == injectedDllPath {
			return uintptr(modules[i]), nil
		}
	}
	return 0, nil
}

func callRemoteFunction(processID uint32, dllBaseAddress uintptr, functionName string, functionRVA uintptr, args []string) error {
	processHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_CREATE_THREAD, false, processID)
	if err != nil {
		return fmt.Errorf("error opening process: %w", err)
	}
	defer windows.CloseHandle(processHandle)

	totalSize := uintptr(0)
	for _, arg := range args {
		totalSize += uintptr(len(arg)*2 + 2)
	}
	totalSize += uintptr(len(args)) * unsafe.Sizeof(uintptr(0))
	remoteArgBlock := uintptr(0)
	if totalSize > 0 {
		remoteArgBlock, _, err := virtualAllocEx.Call(
			uintptr(processHandle),
			0,
			totalSize,
			uintptr(MEM_RESERVE|MEM_COMMIT),
			uintptr(windows.PAGE_READWRITE),
		)
		if remoteArgBlock == 0 {
			return fmt.Errorf("VirtualAllocEx failed: %v", err)
		}
		defer virtualFreeEx.Call(uintptr(processHandle), remoteArgBlock, 0, windows.MEM_RELEASE)
	}

	remotePointers := make([]uintptr, len(args))
	currentOffset := uintptr(0)

	for i, arg := range args {
		argUTF16, err := windows.UTF16FromString(arg)
		if err != nil {
			return fmt.Errorf("UTF16FromString failed: %w", err)
		}
		argSize := uintptr(len(argUTF16) * 2)

		remoteArgAddress := remoteArgBlock + currentOffset
		remotePointers[i] = remoteArgAddress

		bytesWritten := uint(0)
		_, _, err = writeProcessMemory.Call(
			uintptr(processHandle),
			remoteArgAddress,
			uintptr(unsafe.Pointer(&argUTF16[0])),
			argSize,
			uintptr(unsafe.Pointer(&bytesWritten)),
		)
		if uintptr(bytesWritten) != argSize {
			return fmt.Errorf("WriteProcessMemory failed for arg '%s': %w", arg, err)
		}
		currentOffset += argSize
	}

	var argToPass uintptr
	if len(remotePointers) > 0 {
		argToPass = remotePointers[0]
	}

	remoteFunctionAddress := dllBaseAddress + functionRVA
	threadHandle, _, err := createRemoteThread.Call(
		uintptr(processHandle),
		0,
		0,
		remoteFunctionAddress,
		argToPass,
		0,
		0,
	)
	if threadHandle == 0 {
		return fmt.Errorf("CreateRemoteThread failed while calling '%s': %v", functionName, err)
	}
	defer syscall.CloseHandle(syscall.Handle(threadHandle))

	_, err = syscall.WaitForSingleObject(syscall.Handle(threadHandle), syscall.INFINITE)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject failed: %w", err)
	}

	return nil
}

func injectInProcess(processID uint32, processName string, dllPath string, dllFunction string, dllFunctionArgs []string) error {
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Opening process %s with 0x%x access...", processID, processName, windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION))
	processHandle, err := syscall.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION, false, processID)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer syscall.CloseHandle(processHandle)

	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Process Handle: 0x%x", processID, processHandle))
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Loading DLL: %s", processID, dllPath))
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - DLL Path Length: %d", processID, len(dllPath)))

	dllBaseAddress, err := injectDLL(processID, windows.Handle(processHandle), dllPath)
	if err != nil || dllBaseAddress == 0 {
		if err == nil {
			err = fmt.Errorf("DLL base address is 0")
		}
		return fmt.Errorf("DLL injection failed: %v", err)
	}
	logMessage(LOGLEVEL_INFO, fmt.Sprintf("PID: %d - DLL injected successfully.", processID))

	FunctionRVA, err := findSymbolRVA(dllPath, dllFunction)
	if err != nil {
		return fmt.Errorf("error finding symbol RVA: %v", err)
	}
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Function '%s' RVA: 0x%x", processID, dllFunction, FunctionRVA))

	err = callRemoteFunction(processID, dllBaseAddress, dllFunction, uintptr(FunctionRVA), dllFunctionArgs)
	if err != nil {
		return fmt.Errorf("error calling remote function: %v", err)
	}
	logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Function '%s' successfully called.", processID, dllFunction))

	return nil
}
