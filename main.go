package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
)

func main() {
	// Fill this variables to make it work
	injectProcessNameList := []string{"notepad.exe"} // List of process names to inject into
	injectionDLLPath := "C:\\Temp\\MyDll.dll"        // Path to the DLL to inject
	injectionFunctionName := "MyInjectFunction"      // Name of the function to call in the DLL

	SetLogLevel(LOGLEVEL_DEBUG)
	logMessage(LOGLEVEL_INFO, "Starting process injection...\n")

	for {
		processes, error := process.Processes()
		if error != nil {
			logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Error getting processes: %v\n", error))
			continue
		}

		for _, process := range processes {
			processName, error := process.Name()
			if error != nil {
				logMessage(LOGLEVEL_ERROR, fmt.Sprintf("Error getting process name: %v\n", error))
				continue
			}

			for _, proc := range injectProcessNameList {
				if strings.EqualFold(proc, processName) {
					modHandle, err := GetInjectedLibraryModuleHandle(uint32(process.Pid), injectionDLLPath)
					if err != nil {
						logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d Error checking module handle: %v\n", process.Pid, err))
						continue
					}

					if modHandle == 0 {
						logMessage(LOGLEVEL_INFO, fmt.Sprintf("Found process: %s (PID: %d)\n", processName, process.Pid))
						injectInProcess(uint32(process.Pid), processName, injectionDLLPath, injectionFunctionName)
					} else {
						logMessage(LOGLEVEL_WARNING, fmt.Sprintf("Process %s (PID: %d) is already injected.\n", processName, process.Pid))
					}
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}
