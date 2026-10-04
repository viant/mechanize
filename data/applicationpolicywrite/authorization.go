package applicationpolicywrite

import (
	"context"
	"fmt"
	"github.com/viant/mechanize/data"
)

func (input *WriteApplicationPolicyInput) Init(ctx context.Context) error {
	a, err := data.RequireApplicationPolicyAuthority(ctx, input.Namespace)
	if err != nil {
		return err
	}
	if input.ExpectedRevision != a.ExpectedRevision || len(input.Applicationpolicywrite) != 1 || input.Applicationpolicywrite[0] == nil {
		return fmt.Errorf("exactly one authorized policy and expected revision required")
	}
	e := input.Applicationpolicywrite[0]
	if e.Namespace == nil || *e.Namespace != input.Namespace || e.Id == nil || *e.Id != data.ApplicationPolicyID || e.Revision == nil || *e.Revision != input.ExpectedRevision {
		return fmt.Errorf("policy identity and expected revision mismatch")
	}
	return nil
}
