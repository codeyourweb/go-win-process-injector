package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func FindProcessID(processName string) (uint32, error) {
	snapshot, _, _ := createToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if snapshot == 0 {
		return 0, fmt.Errorf("failed to create snapshot. Error: %d", syscall.GetLastError())
	}
	defer syscall.CloseHandle(syscall.Handle(snapshot))

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	ret, _, _ := process32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0, fmt.Errorf("failed to retrieve first process entry. Error: %d", syscall.GetLastError())
	}

	for {
		exeFile := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(exeFile, processName) {
			return entry.ProcessID, nil
		}

		ret, _, _ := process32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return 0, fmt.Errorf("process not found: %s", processName)
}
