package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/akamensky/argparse"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

func injectorRoutine(injectProcessNameList []string, injectionDLLPath string, injectionFunctionName string, injectionFunctionArg string, refreshInterval int, maxInjectionRetry int, quit <-chan struct{}) {
	// initial process injection (for already running processes)
	processes, error := process.Processes()
	if error != nil {
		logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Error getting processes: %v", error))
	}

	for _, proc := range processes {
		processName, error := proc.Name()
		if error != nil {
			logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("Error getting process name for PID %d: %v", proc.Pid, error))
			continue
		}

		if isProcessNameInList(processName, injectProcessNameList) {
			go func() {
				HandleProcessInjection(processName, uint32(proc.Pid), injectionDLLPath, injectionFunctionName, injectionFunctionArg, refreshInterval, maxInjectionRetry)
			}()
		}
	}

	// communication channels for WMI service
	wmiRequests := make(chan wmiServiceRequest)
	wmiResponses := make(chan wmiServiceResponse)

	// start WMI service goroutine
	go wmiService(wmiRequests, wmiResponses)

	logMessage(LOGLEVEL_INFO, "Process injector service started.")

	for {
		select {
		case <-quit:
			logMessage(LOGLEVEL_INFO, "Shutting down process injector service.")
			close(wmiRequests)
			return

		case resp := <-wmiResponses:
			if resp.err != nil {
				logMessage(LOGLEVEL_ERROR, fmt.Sprintf("WMI service error: %v", resp.err))
				if hresult, ok := resp.err.(syscall.Errno); ok {
					if hresult != 0x80041006 { // ignore "not available" error which can be temporary
						return
					}
				}
				continue
			}

			event := resp.event
			logMessage(LOGLEVEL_DEBUG, fmt.Sprintf("New process detected: Name=%s, PID=%d", event.Name, event.PID))

			// If the process name is in the list, attempt injection
			if isProcessNameInList(event.Name, injectProcessNameList) {
				go func() {
					HandleProcessInjection(event.Name, event.PID, injectionDLLPath, injectionFunctionName, injectionFunctionArg, refreshInterval, maxInjectionRetry)
				}()
			}
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
