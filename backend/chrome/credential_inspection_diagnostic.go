package chrome

var inspectionPredicateReasons = map[string]string{
	"originUnavailable": "OriginUnavailable", "fieldLimit": "FieldLimit", "visibleChallengeControl": "VisibleChallengeControl", "inactiveChallengeControl": "InactiveChallengeControl", "hiddenChallengeControl": "HiddenChallengeControl", "ambiguousPasswordFields": "AmbiguousPasswordFields", "newPasswordField": "NewPasswordField", "ambiguousUsernameFields": "AmbiguousUsernameFields", "noCredentialFields": "NoCredentialFields", "missingForm": "MissingForm", "differentForms": "DifferentForms", "unsafeFormAction": "UnsafeFormAction", "unsafeFormTarget": "UnsafeFormTarget", "formControlLimit": "FormControlLimit", "unsupportedFormControl": "UnsupportedFormControl", "formDetached": "FormDetached", "unsupportedFormMethod": "UnsupportedFormMethod", "submitUnavailable": "SubmitUnavailable", "missingSubmitter": "MissingSubmitter", "ambiguousSubmitter": "AmbiguousSubmitter", "submitterDisabled": "SubmitterDisabled", "unsafeSubmitter": "UnsafeSubmitter", "documentBindingOrProtectionUnavailable": "BindingOrProtectionUnavailable",
}

// Closed causes only. No DOM metadata, values, selectors, URLs or error text.
func closedInspectionReason(reason string) bool {
	if _, ok := inspectionPredicateReasons[reason]; ok {
		return true
	}
	switch reason {
	case "none", "requestInvalid", "workerAuthorityUnavailable", "documentUnavailable", "documentChanged", "rendererBindingUnavailable", "rendererReplyUnavailable", "rendererProtocolUnavailable", "documentBindingUnavailable", "privateDocumentProtected", "privateInputRetained", "recipientUnavailable", "recipientChanged", "readinessUnavailable", "challenge", "fieldsUnavailable", "submitterUnavailable", "replyUnavailable", "replyInvalid", "replyCorrelationUnavailable":
		return true
	}
	return false
}
func CredentialInspectionAttention(reason string) string {
	if suffix, ok := inspectionPredicateReasons[reason]; ok {
		return "privateInspection" + suffix
	}
	switch reason {
	case "workerAuthorityUnavailable":
		return "privateInspectionWorkerAuthorityUnavailable"
	case "documentUnavailable", "documentChanged":
		return "privateInspectionDocumentUnavailable"
	case "rendererBindingUnavailable", "documentBindingUnavailable":
		return "privateInspectionBindingUnavailable"
	case "rendererReplyUnavailable", "replyUnavailable":
		return "privateInspectionReplyUnavailable"
	case "rendererProtocolUnavailable", "requestInvalid", "replyInvalid":
		return "privateInspectionProtocolUnavailable"
	case "replyCorrelationUnavailable":
		return "privateInspectionCorrelationUnavailable"
	case "privateDocumentProtected":
		return "privateInspectionDocumentProtected"
	case "privateInputRetained":
		return "privateInspectionInputRetained"
	case "recipientChanged":
		return "privateInspectionRecipientChanged"
	case "fieldsUnavailable":
		return "privateInspectionFieldsUnavailable"
	case "submitterUnavailable":
		return "privateInspectionSubmitterUnavailable"
	case "challenge":
		return "privateInspectionChallenge"
	case "recipientUnavailable", "readinessUnavailable":
		return "privateInspectionFormUnavailable"
	}
	return "privateInspectionUnavailable"
}

// CredentialInspectionAttentionCodes is the finite public projection vocabulary.
// Consumers validate exact membership, never a prefix or arbitrary error text.
func CredentialInspectionAttentionCodes() []string {
	codes := map[string]bool{}
	for reason := range inspectionPredicateReasons {
		codes[CredentialInspectionAttention(reason)] = true
	}
	for _, reason := range []string{"workerAuthorityUnavailable", "documentUnavailable", "documentBindingUnavailable", "replyUnavailable", "requestInvalid", "replyCorrelationUnavailable", "privateDocumentProtected", "privateInputRetained", "recipientChanged", "fieldsUnavailable", "submitterUnavailable", "challenge", "readinessUnavailable", "none"} {
		codes[CredentialInspectionAttention(reason)] = true
	}
	result := make([]string, 0, len(codes))
	for code := range codes {
		result = append(result, code)
	}
	return result
}
func ValidCredentialInspectionAttention(code string) bool {
	for _, known := range CredentialInspectionAttentionCodes() {
		if code == known {
			return true
		}
	}
	return false
}
