package main

import (
	"fmt"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

type wmiEvent struct {
	Name string
	PID  uint32
}

type wmiServiceRequest struct {
	quit chan struct{}
}

type wmiServiceResponse struct {
	event *wmiEvent
	err   error
}

// wmiService goroutine will monitor process creation events using WMI and sends events back via the response channel.
func wmiService(request <-chan wmiServiceRequest, response chan<- wmiServiceResponse) {
	// Initialize COM once for this goroutine
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	if err != nil {
		response <- wmiServiceResponse{err: fmt.Errorf("COM initialization failed: %v", err)}
		return
	}
	defer ole.CoUninitialize()

	// Initialize WMI once for this goroutine
	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		response <- wmiServiceResponse{err: fmt.Errorf("failed to create WMI locator: %v", err)}
		return
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		response <- wmiServiceResponse{err: fmt.Errorf("failed to query WMI interface: %v", err)}
		return
	}
	defer wmi.Release()

	service, err := oleutil.CallMethod(wmi, "ConnectServer", nil, "root\\cimv2")
	if err != nil {
		response <- wmiServiceResponse{err: fmt.Errorf("failed to connect to WMI service: %v", err)}
		return
	}
	defer service.Clear()

	query := `SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'`
	eventSource, err := oleutil.CallMethod(service.ToIDispatch(), "ExecNotificationQuery", query)
	if err != nil {
		response <- wmiServiceResponse{err: fmt.Errorf("failed to execute WMI notification query: %v", err)}
		return
	}
	defer eventSource.Clear()

	logMessage(LOGLEVEL_INFO, "WMI service ready and monitoring processes...")

	for {
		// WMI service main loop
		ret, err := oleutil.CallMethod(eventSource.ToIDispatch(), "NextEvent")
		if err != nil {
			response <- wmiServiceResponse{err: fmt.Errorf("error retrieving WMI event: %v", err)}
			return
		}

		eventObject := ret.ToIDispatch()

		targetInstance, err := oleutil.GetProperty(eventObject, "TargetInstance")
		if err != nil {
			eventObject.Release()
			response <- wmiServiceResponse{err: fmt.Errorf("error retrieving TargetInstance: %v", err)}
			continue
		}

		procInfo := targetInstance.ToIDispatch()
		processName, _ := oleutil.GetProperty(procInfo, "Name")
		pid, _ := oleutil.GetProperty(procInfo, "ProcessId")

		response <- wmiServiceResponse{
			event: &wmiEvent{
				Name: processName.ToString(),
				PID:  uint32(pid.Val),
			},
		}

		targetInstance.Clear()
		eventObject.Release()
	}
}
