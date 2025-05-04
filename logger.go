package main

import (
	"fmt"
	"time"
)

const (
	LOGLEVEL_ERROR   = 0
	LOGLEVEL_INFO    = 1
	LOGLEVEL_WARNING = 2
	LOGLEVEL_DEBUG   = 3
)

var currentLogLevel = LOGLEVEL_INFO

func SetLogLevel(logLevel int) {
	if logLevel >= LOGLEVEL_INFO && logLevel <= LOGLEVEL_DEBUG {
		currentLogLevel = logLevel
	} else {
		fmt.Println("Niveau de logging invalide. Utilisation du niveau INFO par défaut.")
		currentLogLevel = LOGLEVEL_INFO
	}
}

func logMessage(logLevel int, message string) {
	if logLevel <= currentLogLevel {
		currentTime := time.Now().Format("2006-01-02 15:04:05")
		logLevels := []string{"ERROR", "INFO", "WARNING", "DEBUG"}
		logMessage := fmt.Sprintf("[%s] [%s] %s", currentTime, logLevels[logLevel], message)
		fmt.Print(logMessage)
	}
}
