//go:build darwin && cgo

package main

import (
	"errors"
	"testing"
)

func TestInvalidPointIsRejectedBeforeMouseDown(t *testing.T) {
	if got := MechanizeRobotGoDown(100001, 0); got != 2 {
		t.Fatalf("invalid coordinate must carry explicit pre-post rejection, got %d", got)
	}
}

func TestPointerDownDistinguishesPrePostRejectionAndUncertainty(t *testing.T) {
	for _, mode := range []string{"moved", "posted", "driverError", "driverPanic", "observationPanic"} {
		t.Run(mode, func(t *testing.T) {
			posts := 0
			got := pointerDown(10, 20, func(float64, float64) bool {
				if mode == "observationPanic" {
					panic("fixture")
				}
				return mode != "moved"
			}, func() error {
				posts++
				if mode == "driverPanic" {
					panic("fixture")
				}
				if mode == "driverError" {
					return errors.New("fixture")
				}
				return nil
			})
			want, wantPosts := 1, 1
			if mode == "moved" {
				want, wantPosts = 2, 0
			}
			if mode == "observationPanic" {
				wantPosts = 0
			}
			if mode == "posted" {
				want = 0
			}
			if got != want || posts != wantPosts {
				t.Fatalf("result=%d posts=%d; want %d/%d", got, posts, want, wantPosts)
			}
		})
	}
}
