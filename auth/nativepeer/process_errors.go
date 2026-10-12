package nativepeer

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrNativePeerAuthentication              = errors.New("native peer socket authentication unavailable")
	ErrNativePeerAudit                       = errors.New("native peer socket audit unavailable or changed")
	ErrRunningImageMismatch                  = errors.New("running native image differs from enrollment")
	ErrNativeHostSignatureUnavailable        = errors.New("native host static signature unavailable")
	ErrChromeSignatureUnavailable            = errors.New("Chrome signature unavailable")
	ErrNativeHostProcessUnavailable          = errors.New("native host process identity unavailable")
	ErrNativeHostUIDUnavailable              = errors.New("native host UID differs from enrollment")
	ErrNativeHostDynamicSignatureUnavailable = errors.New("native host dynamic signature unavailable")
	ErrChromeAncestryUnavailable             = errors.New("Chrome ancestry unavailable within enrolled bound")
	ErrChromeParentUnavailable               = errors.New("Chrome parent identity unavailable")
	ErrAncestryChanged                       = errors.New("process ancestry changed during verification")
)

type processStageFailure struct{ stage, cause error }

func (e *processStageFailure) Error() string              { return e.stage.Error() }
func (e *processStageFailure) Is(target error) bool       { return target == e.stage }
func (e *processStageFailure) Unwrap() error              { return e.cause }
func (e *processStageFailure) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }

// ProcessFailure retains internal errors.Is identity without exposing raw
// libproc/Security errors, paths or other diagnostic material through formatting.
func ProcessFailure(stage, cause error) error {
	switch stage {
	case ErrRunningImageMismatch, ErrNativeHostSignatureUnavailable, ErrChromeSignatureUnavailable, ErrNativeHostProcessUnavailable, ErrNativeHostUIDUnavailable, ErrNativeHostDynamicSignatureUnavailable, ErrChromeAncestryUnavailable, ErrChromeParentUnavailable, ErrAncestryChanged:
	default:
		stage = ErrNativeHostProcessUnavailable
	}
	return &processStageFailure{stage: stage, cause: cause}
}
