package main

import "strings"

func isPidInExclusion(list []uint32, item uint32) bool {
	for _, v := range list {
		if v == item {
			return true
		}
	}
	return false
}

func isProcessNameInList(processName string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(v, processName) {
			return true
		}
	}
	return false
}
