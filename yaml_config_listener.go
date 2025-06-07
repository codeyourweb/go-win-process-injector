package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var AppConfig MainConfig

type MainConfig struct {
	InjectorLogLevel  string             `yaml:"injector_log_level"`
	InjectorLogFile   string             `yaml:"injector_log_file"`
	ProcessInjections []ProcessInjection `yaml:"process_injections"`
}

type ProcessInjection struct {
	Name                            string   `yaml:"name"`
	Processes                       []string `yaml:"processes"`
	ProcessInjectionDLLPath         string   `yaml:"process_injection_dll_path"`
	ProcessInjectionDLLFunction     string   `yaml:"process_injection_dll_function"`
	ProcessInjectionRefreshInterval int      `yaml:"process_injection_refresh_interval"`
}

func LoadConfig(configPath string) error {
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for config file '%s': %w", configPath, err)
	}

	configData, err := os.ReadFile(absConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file '%s': %w", absConfigPath, err)
	}

	err = yaml.Unmarshal(configData, &AppConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config data from '%s': %w", absConfigPath, err)
	}

	if AppConfig.InjectorLogLevel == "" {
		AppConfig.InjectorLogLevel = "LOGLEVEL_INFO"
	}
	AppConfig.InjectorLogLevel = strings.ToUpper(AppConfig.InjectorLogLevel)

	if AppConfig.InjectorLogFile == "" {
		AppConfig.InjectorLogFile = "C:\\Windows\\Temp\\goprocinjector.log"
	}

	for i, pi := range AppConfig.ProcessInjections {
		if pi.ProcessInjectionRefreshInterval == 0 {
			AppConfig.ProcessInjections[i].ProcessInjectionRefreshInterval = 5 // Default to 5 seconds
		}
		if pi.ProcessInjectionDLLPath == "" {
			return fmt.Errorf("configuration error: process_injection_dll_path cannot be empty for injection '%s'", pi.Name)
		}
		if pi.ProcessInjectionDLLFunction == "" {
			return fmt.Errorf("configuration error: process_injection_dll_function cannot be empty for injection '%s'", pi.Name)
		}
		if len(pi.Processes) == 0 {
			return fmt.Errorf("configuration error: processes list cannot be empty for injection '%s'", pi.Name)
		}
	}

	return nil
}
