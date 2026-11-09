package main

import "regexp"

var safeName = regexp.MustCompile(`^[a-zA-Z]+$`)

func clean(s string) string {
	if safeName.MatchString(s) {
		return s
	}
	return "default"
}
