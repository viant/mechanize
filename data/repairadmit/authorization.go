package repairadmit

import (
	"context"
	"errors"
	"github.com/viant/mechanize/data"
	"reflect"
)

func (input *AdmitRepairInput) Init(ctx context.Context) error {
	if _, err := data.RequireScope(ctx, input.Namespace); err != nil {
		return err
	}
	if len(input.AdmitRepair) != 1 {
		return errors.New("one bounded repair admission required")
	}
	permit, err := requirePermit(ctx)
	if err != nil {
		return err
	}
	if input.RunID != permit.RunID || input.ParentPlanID != permit.ParentPlanID || input.AnchorID != permit.AnchorID {
		return errors.New("exact verified repair scope anchor required")
	}
	if len(input.AdmitRepair) != 1 || input.AdmitRepair[0].Id == nil || *input.AdmitRepair[0].Id != permit.AnchorID || input.AdmitRepair[0].Records == nil || len(input.AdmitRepair[0].Plans) != 1 {
		return errors.New("bounded immutable repair scope required")
	}
	// Reject foreign ingress before generated relation producers reconcile parent
	// keys. Reconciliation cannot turn a caller's namespace claim into authority.
	var inspect func(reflect.Value) error
	inspect = func(v reflect.Value) error {
		if !v.IsValid() {
			return nil
		}
		switch v.Kind() {
		case reflect.Pointer:
			if !v.IsNil() {
				return inspect(v.Elem())
			}
		case reflect.Struct:
			if field := v.FieldByName("Namespace"); field.IsValid() && field.Kind() == reflect.Pointer {
				if field.IsNil() || field.Elem().String() != permit.Namespace {
					return errors.New("foreign repair namespace ingress")
				}
			}
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).Name == "Has" {
					continue
				}
				if err := inspect(v.Field(i)); err != nil {
					return err
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if err := inspect(v.Index(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return inspect(reflect.ValueOf(input.AdmitRepair))
}
