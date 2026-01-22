package main

import "fmt"

func processSlice(nums []int) int {
	sum := 0
	for _, n := range nums {
		sum += n
	}
	return sum
}

func processString(s string) int {
	return len(s)
}

func main() {
	nums := []int{1, 2, 3, 4, 5}
	result := processSlice(nums)
	fmt.Println("Sum:", result)

	str := "hello"
	length := processString(str)
	fmt.Println("Length:", length)
}
