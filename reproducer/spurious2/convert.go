package main

import "strconv"

func toID(s string) int {
n, err := strconv.Atoi(s)
if err != nil {
return 0
}
return n
}
