package model

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf16"
)

// This is the authored contract of the enrolled web.valueEquals adapter. It
// validates syntax/types only and never supplies document or read authority.
func (p Predicate) validateWebValueEquals() error {
	refuse := func(message string) error {
		return &MechanizeError{Code: "invalidPredicate", Message: message, Stage: "validation", DispatchState: "notDispatched", EffectState: "none"}
	}
	if p.RequiredAuthority != "observational" {
		return refuse("web.valueEquals requires requiredAuthority observational.")
	}
	if p.TimeoutMs > 30000 {
		return refuse("web.valueEquals timeoutMs must not exceed 30000.")
	}
	kinds := map[string]ValueKind{}
	for _, key := range []string{"origin", "strategy", "selector", "name", "attribute", "expected", "order", "profileChannel", "browserInstance", "documentId", "extensionOrigin", "brokerEpoch", "channelEpoch", "scopeHash"} {
		kinds[key] = StringValue
	}
	for _, key := range []string{"tabId", "frameId", "documentGeneration", "index"} {
		kinds[key] = NumberValue
	}
	for key, value := range p.Inputs {
		kind, ok := kinds[key]
		if !ok {
			return refuse("web.valueEquals uses inputs.strategy and inputs.selector; use strategy id with selector set to the element ID.")
		}
		if value.Kind == ReferenceValue {
			if value.Expected != "" && value.Expected != kind {
				return refuse("web.valueEquals input reference has an incompatible type.")
			}
			continue
		}
		if value.Kind != kind {
			return refuse("web.valueEquals inputs require their declared string or number types.")
		}
		if kind == StringValue {
			max := 256
			switch key {
			case "origin":
				max = 2048
			case "selector", "name":
				max = 1024
			case "strategy", "attribute", "order":
				max = 16
			case "expected":
				max = 4096
			}
			if len(value.String) > max || key != "expected" && strings.TrimSpace(value.String) == "" {
				return refuse("web.valueEquals string input is outside its bounded contract.")
			}
			for _, r := range value.String {
				if unicode.IsControl(r) {
					return refuse("web.valueEquals string input contains unsupported control characters.")
				}
			}
		}
	}
	for _, key := range []string{"origin", "strategy", "selector", "attribute", "expected"} {
		if _, ok := p.Inputs[key]; !ok {
			return refuse("web.valueEquals requires typed origin, strategy, selector, attribute and expected inputs.")
		}
	}
	literal := func(key string) string {
		v := p.Inputs[key]
		if v.Kind == StringValue {
			return v.String
		}
		return ""
	}
	if v := p.Inputs["origin"]; v.Kind == StringValue {
		u, e := url.Parse(v.String)
		if e != nil || !ExactHTTPOrigin(v.String) || u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			return refuse("web.valueEquals origin must be exact HTTPS or HTTP loopback.")
		}
	}
	if s := literal("strategy"); s != "" && s != "id" && s != "testId" && s != "role" && s != "label" {
		return refuse("web.valueEquals strategy must be id, testId, role or label.")
	}
	if a := literal("attribute"); a != "" && a != "value" && a != "text" && a != "name" {
		return refuse("web.valueEquals attribute must be value, text or name.")
	}
	if e := p.Inputs["expected"]; e.Kind == StringValue && len(utf16.Encode([]rune(e.String))) >= 256 {
		return refuse("web.valueEquals expected value must be shorter than 256 UTF-16 units.")
	}
	if _, named := p.Inputs["name"]; named && literal("strategy") != "" && literal("strategy") != "role" {
		return refuse("web.valueEquals name requires a role selector.")
	}
	index, hasIndex := p.Inputs["index"]
	_, hasOrder := p.Inputs["order"]
	if hasIndex != hasOrder {
		return refuse("web.valueEquals indexed reads require index and order document together.")
	}
	if hasIndex && (index.Kind == NumberValue && (index.Number < 0 || index.Number > 999) || literal("order") != "" && literal("order") != "document") {
		return refuse("web.valueEquals index must be 0..999 with order document.")
	}
	for key, bounds := range map[string][2]int64{"tabId": {1, 2147483647}, "frameId": {0, 0}, "documentGeneration": {1, 9007199254740991}} {
		if v, ok := p.Inputs[key]; ok && v.Kind == NumberValue && (v.Number < bounds[0] || v.Number > bounds[1]) {
			return refuse("web.valueEquals identity hint is outside its bounded contract.")
		}
	}
	return nil
}
