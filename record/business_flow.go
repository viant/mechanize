package record

import "errors"

type FlowEvidence struct {
	Sequences []uint64             `json:"sequences,omitempty"`
	Lineages  []string             `json:"lineages,omitempty"`
	Frames    []VideoFrameEvidence `json:"frames,omitempty"`
}
type BusinessFlowStep struct {
	Kind           string       `json:"kind"`
	Status         string       `json:"status"`
	ProposedAction string       `json:"proposedAction,omitempty"`
	Evidence       FlowEvidence `json:"evidence"`
	ReviewIssues   []Issue      `json:"reviewIssues,omitempty"`
}
type BusinessFlowDraft struct {
	Goal                    string             `json:"goal"`
	GoalStatus              string             `json:"goalStatus"`
	Steps                   []BusinessFlowStep `json:"steps"`
	Decisions               []BusinessFlowStep `json:"decisions"`
	Checkpoints             []BusinessFlowStep `json:"checkpoints"`
	Gaps                    []RecordGap        `json:"gaps,omitempty"`
	ProposedDSL             Export             `json:"proposedDsl"`
	Qualification           string             `json:"qualification"`
	BusinessSuccess         bool               `json:"businessSuccess"`
	SystemRollbackAvailable bool               `json:"systemRollbackAvailable"`
}

// DraftBusinessFlow uses the existing shared DSL compiler, preserving its withheld
// inputs and unresolved targets. It does not infer decisions or business success
// from screenshots. Goals/checkpoints are explicitly supplied review proposals.
func DraftBusinessFlow(goal string, request Request, batch RecordBatch, video VideoTimeline) (BusinessFlowDraft, error) {
	if goal == "" || len(goal) > 2048 || batch.RecordingID != video.RecordingID || len(batch.Gaps) > 64 {
		return BusinessFlowDraft{}, errors.New("bounded goal and matching video recording required")
	}
	links, err := CorrelateVideo(batch.Events, video, 1000)
	if err != nil {
		return BusinessFlowDraft{}, err
	}
	gaps := append(append([]RecordGap(nil), batch.Gaps...), video.Gaps...)
	if len(video.Frames) == 0 {
		gaps = append(gaps, RecordGap{Kind: "gap", Reason: "videoFramesUnavailable", UnknownExtent: true})
	}
	if batch.Truncated {
		gaps = append(gaps, RecordGap{Kind: "gap", Reason: "recordingTruncated", UnknownExtent: true})
	}
	if video.State != "stopped" || batch.State != "stopped" {
		gaps = append(gaps, RecordGap{Kind: "gap", Reason: "captureStopUnconfirmed", UnknownExtent: true})
	}
	exported, err := (Compiler{}).Compile(request, batch.Events, gaps)
	if err != nil {
		return BusinessFlowDraft{}, err
	}
	out := BusinessFlowDraft{Goal: goal, GoalStatus: "userDeclared", Qualification: "unqualified", ProposedDSL: exported, Gaps: gaps, Steps: []BusinessFlowStep{}, Decisions: []BusinessFlowStep{}, Checkpoints: []BusinessFlowStep{}}
	indexed := map[uint64]EventVideoEvidence{}
	for _, link := range links {
		indexed[link.EventSequence] = link
	}
	for _, action := range exported.DraftActions {
		link := indexed[action.Sequence]
		step := BusinessFlowStep{Kind: action.CapturedKind, Status: "observedUnattested", ProposedAction: action.ProposedAction, Evidence: FlowEvidence{Sequences: []uint64{action.Sequence}, Lineages: []string{action.Lineage}, Frames: link.Frames}, ReviewIssues: action.ReviewIssues}
		out.Steps = append(out.Steps, step)
		if action.Checkpoint != nil {
			out.Checkpoints = append(out.Checkpoints, BusinessFlowStep{Kind: "checkpoint", Status: "proposedNeedsIndependentVerification", Evidence: step.Evidence})
		}
	}
	// A decision requires evidence of alternatives/selection; ordinary presses
	// and video proximity cannot establish one. Preserve the explicit review gap.
	out.Gaps = append(out.Gaps, RecordGap{Kind: "gap", Reason: "businessDecisionsAndOutcomeRequireReview", UnknownExtent: true})
	return out, nil
}
