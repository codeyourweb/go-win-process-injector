package main

import (
	"log"
	"sync"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

type pInjectService struct{}

func (m *pInjectService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {

	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	var (
		wg             sync.WaitGroup
		quitInjector   chan struct{}
		injectorActive bool
	)

	startInjectorGoroutine := func() {
		if injectorActive {
			return
		}
		quitInjector = make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, inject := range AppConfig.ProcessInjections {
				go injectorRoutine(inject.Processes,
					inject.ProcessInjectionDLLPath,
					inject.ProcessInjectionDLLFunction,
					inject.ProcessInjectionDLLFunctionArgs,
					inject.ProcessInjectionRefreshInterval,
					quitInjector)
			}
		}()
		injectorActive = true
	}

	stopInjectorGoroutine := func() {
		if !injectorActive {
			return
		}
		close(quitInjector)
		wg.Wait()
		injectorActive = false
	}

	startInjectorGoroutine()

serviceLoop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logMessage(LOGLEVEL_INFO, "Shutting down process injector service.")
				stopInjectorGoroutine()
				break serviceLoop
			default:
				log.Printf("Unexpected service control request #%d", c)
			}
		}
	}

	status <- svc.Status{State: svc.StopPending}
	return false, 0
}

func runService(name string, isDebug bool) {
	if isDebug {
		err := debug.Run(name, &pInjectService{})
		if err != nil {
			log.Fatalln("Error running process injector in interactive mode:", err)
		}
	} else {
		err := svc.Run(name, &pInjectService{})
		if err != nil {
			log.Fatalln("Error running process injector in Service Control mode:", err)
		}
	}
}
