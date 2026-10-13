package endly

import "github.com/viant/mechanize/model"

// DispatchedUnverified identifies a completed executor action, never business
// verification. Durable callers also validate the immutable step and row state.
func (r StepResult) DispatchedUnverified() bool {
	return r.DispatchState == "dispatched" && r.VerificationState == "unverified" && r.Postcondition == nil
}

// CompletedForResume accepts only a verified result or the receipt of an action
// that did not promise a postcondition. It authorizes skipping, never replaying.
func (r StepResult) CompletedForResume(step model.Step) bool {
	return r.VerificationState == "verified" || step.Postcondition == nil && r.DispatchedUnverified()
}
