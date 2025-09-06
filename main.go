package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/akamensky/argparse"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

func injectorRoutine(injectProcessNameList []string, injectionDLLPath string, injectionFunctionName string, injectionFunctionArg string, refreshInterval int, quit <-chan struct{}) {
	excludedPID := []uint32{0}

	logMessage(LOGLEVEL_INFO, "Injector routine started.")

	ticker := time.NewTicker(time.Duration(refreshInterval) * time.Second)
	tickerActive := true

	for {
		select {
		case <-ticker.C:
			select {
			case <-quit:
				logMessage(LOGLEVEL_INFO, "Shutting down process injector service.")
				ticker.Stop()
				return
			default:
			}

			processes, error := process.Processes()
			if error != nil {
				logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Error getting processes: %v", error))
				continue
			}

			for _, proc := range processes {
				select {
				case <-quit:
					logMessage(LOGLEVEL_INFO, "Shutting down process injector service.")
					ticker.Stop()
					return
				default:
				}

				processName, error := proc.Name()
				if error != nil {
					logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Error getting process name for PID %d: %v", proc.Pid, error))
					continue
				}

				if isProcessNameInList(processName, injectProcessNameList) {
					modHandle, err := GetInjectedLibraryModuleHandle(uint32(proc.Pid), injectionDLLPath)
					if err != nil {
						logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d Error checking module handle: %v", proc.Pid, err))
						continue
					}

					if modHandle == 0 && !isPidInExclusion(excludedPID, uint32(proc.Pid)) {
						logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Found process to inject: %s (PID: %d)", processName, proc.Pid))
						err = injectInProcess(uint32(proc.Pid), processName, injectionDLLPath, injectionFunctionName, injectionFunctionArg)
						if err != nil {
							logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID: %d - Error injecting DLL: %v", proc.Pid, err))
						} else {
							excludedPID = append(excludedPID, uint32(proc.Pid))
							logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("PID %d added to exclusion list.", proc.Pid))
						}
					} else if modHandle != 0 {
						logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Process %s (PID: %d) is already injected (handle: %x).", processName, proc.Pid, modHandle))
					} else {
						logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Process %s (PID: %d) is in exclusion list.", processName, proc.Pid))
					}
				}
			}

		case <-quit:
			logMessage(LOGLEVEL_INFO, "Shutting down process injector service.")
			if tickerActive {
				ticker.Stop()
			}
			return
		}
	}
}

func main() {
	// config file argument parsing
	parser := argparse.NewParser("Go Process Injector", "Process Injector Service for Windows")
	configFilePath := parser.String("c", "config", &argparse.Options{Required: true, Help: "YAML configuration file"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	// load yaml configuration
	err = LoadConfig(*configFilePath)
	if err != nil {
		log.Fatalln(fmt.Errorf("error loading configuration: %v", err))
	}

	// initialize logger
	var APP_LOGLEVEL int
	switch AppConfig.InjectorLogLevel {
	case "LOGLEVEL_DEBUG":
		APP_LOGLEVEL = LOGLEVEL_DEBUG
	case "LOGLEVEL_WARNING":
		APP_LOGLEVEL = LOGLEVEL_WARNING
	case "LOGLEVEL_ERROR":
		APP_LOGLEVEL = LOGLEVEL_ERROR
	default:
		APP_LOGLEVEL = LOGLEVEL_INFO
	}

	InitLogger(APP_LOGLEVEL)
	if AppConfig.InjectorLogFile != "" {
		SetLogToFile(AppConfig.InjectorLogFile)
	}

	// start in interactive mode or as a Windows service
	isWindowsSerice, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalln(fmt.Errorf("error checking if running as a Windows service: %v", err))
	}

	if isWindowsSerice {
		runService("pInjectService", false)
	} else {
		logMessage(LOGLEVEL_INFO, "Running in interactive mode.")
		err = debug.Run("pInjectService", &pInjectService{})
		if err != nil {
			log.Fatalf("Error running service in interactive mode: %v", err)
		}
		return
	}
}
