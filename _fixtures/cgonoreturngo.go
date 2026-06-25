package main

/*
#include <stdlib.h>

void noreturn_c(void) {
    abort();
}
*/
import "C"

//go:noinline
func goCallsNoreturn() {
	C.noreturn_c()
	// This line never executes, but the return address could
	// land at the start of the next Go function
}

//go:noinline
func anotherGoFunc() {
	println("should not execute")
}

func main() {
	goCallsNoreturn()
	anotherGoFunc()
}
