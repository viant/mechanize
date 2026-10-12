//go:build darwin && cgo

// Package main embeds RobotGo in the existing signed native helper. No separate
// application, input service, credential API or clipboard API is introduced.
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"math"
	"time"

	"github.com/go-vgo/robotgo/darwin"
	"github.com/go-vgo/robotgo/pub"
)

func init() { pub.MouseSleep = 0 }
func validPoint(x, y float64) bool {
	return !math.IsNaN(x) && !math.IsNaN(y) && !math.IsInf(x, 0) && !math.IsInf(y, 0) && math.Abs(x) <= 100000 && math.Abs(y) <= 100000
}
func pointMatches(x, y float64) bool {
	actualX, actualY := darwin.Location()
	return actualX == int(math.Round(x)) && actualY == int(math.Round(y))
}

//export MechanizeRobotGoMove
func MechanizeRobotGoMove(x, y C.double) (result C.int) {
	result = 1
	defer func() {
		if recover() != nil {
			result = 1
		}
	}()
	px, py := float64(x), float64(y)
	if !validPoint(px, py) || darwin.Move(int(math.Round(px)), int(math.Round(py))) != nil {
		return
	}
	// Observe cursor arrival rather than imposing a long fixed input sleep.
	until := time.Now().Add(50 * time.Millisecond)
	for !pointMatches(px, py) {
		if time.Now().After(until) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	return 0
}

//export MechanizeRobotGoDown
func MechanizeRobotGoDown(x, y C.double) (result C.int) {
	result = 1
	defer func() {
		if recover() != nil {
			result = 1
		}
	}()
	if !validPoint(float64(x), float64(y)) || !pointMatches(float64(x), float64(y)) {
		return
	}
	if darwin.MouseDown("left") == nil {
		return 0
	}
	return
}

//export MechanizeRobotGoUp
func MechanizeRobotGoUp() (result C.int) {
	result = 1
	defer func() {
		if recover() != nil {
			result = 1
		}
	}()
	if darwin.MouseUp("left") == nil {
		return 0
	}
	return
}

func main() {}
