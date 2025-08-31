package main

import "C"
import (
	"syscall"
	"unsafe"
)

// Define the struct to match the expected arguments
type MyFunctionArgs struct {
	Arg1 *uint16
	Arg2 *uint16
}

//export FunctionWithArguments
func FunctionWithArguments(argsPtr unsafe.Pointer) {
	args := (*MyFunctionArgs)(argsPtr)
	arg1 := args.Arg1
	arg2 := args.Arg2

	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(
		0,
		uintptr(unsafe.Pointer(arg1)),
		uintptr(unsafe.Pointer(arg2)),
		0,
	)
}

//export FunctionWithoutArgument
func FunctionWithoutArgument() int {
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Test"))),
		0,
	)
	return 42
}
func main() {}
