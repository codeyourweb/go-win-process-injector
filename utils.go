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

func countOccurrences(list []uint32, pid uint32) int {
	count := 0
	for _, v := range list {
		if v == pid {
			count++
		}
	}
	return count
}
