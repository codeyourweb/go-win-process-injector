package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	LOGLEVEL_DEBUG   = 0
	LOGLEVEL_INFO    = 1
	LOGLEVEL_WARNING = 2
	LOGLEVEL_ERROR   = 3
	LOGLEVEL_FATAL   = 4

	LOGLEVEL_DEV_DEBUG_VERBOSE = -1
)

var (
	logFile         *os.File
	currentLogLevel int
	hostname        string
	username        string
	processName     string
	pid             int
)

func InitLogger(level int) {
	currentLogLevel = level
	hostname, _ = os.Hostname()
	username = os.Getenv("USERNAME")
	pid = os.Getpid()
	processName = filepath.Base(os.Args[0])
}

func SetLogToFile(filePath string) {

	if logFile != nil {
		logFile.Close()
	}

	var err error
	logFile, err = os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		logFile = nil
	}
}

func CloseLogger() {
	if logFile != nil {
		logFile.Sync()
		logFile.Close()
		logFile = nil
	}
}

func CleanData(message string) string {
	cleanedData := strings.ReplaceAll(message, "\n", "\\n")
	cleanedData = strings.ReplaceAll(cleanedData, "\r", "\\r")

	return cleanedData
}

func logMessage(level int, message string) {
	if level < currentLogLevel {
		return
	}

	logPrefix := ""
	switch level {
	case LOGLEVEL_DEBUG:
		logPrefix = "DEBUG"
	case LOGLEVEL_INFO:
		logPrefix = "INFO"
	case LOGLEVEL_WARNING:
		logPrefix = "WARNING"
	case LOGLEVEL_ERROR:
		logPrefix = "ERROR"
	case LOGLEVEL_FATAL:
		logPrefix = "FATAL"
	case LOGLEVEL_DEV_DEBUG_VERBOSE:
		logPrefix = "DEV_DEBUG_VERBOSE"
	}

	logEntry := fmt.Sprintf("[%s] [%s] Hostname: %s - Username: %s - ProcessName: %s - PID: %d - Message: %s\n",
		time.Now().Format("2006-01-02 15:04:05.000000"),
		logPrefix,
		hostname,
		username,
		processName,
		pid,
		CleanData(message),
	)

	fmt.Print(logEntry)

	if logFile != nil {
		_, err := logFile.WriteString(logEntry)

		if err != nil {
			fmt.Printf("Error writing to log file: %v\n", err)
		}
	}
}
