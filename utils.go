package main

import "strings"

func isProcessNameInList(processName string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(v, processName) {
			return true
		}
	}
	return false
}
