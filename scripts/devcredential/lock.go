package main

import "github.com/viant/mechanize/internal/devcredential"

func renewalLock(directory string) (func(), error) { return devcredential.Lock(directory) }
