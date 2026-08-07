package db

import "testing"

// TestAWSOrganizationRolloutTargetStateAdvances locks in the promote-only
// rule and its Deploying exception. Inventory reconciliation must be able to
// reopen a Connected target as Deploying when CloudFormation reports an
// active StackSet operation, otherwise the aggregate reports completed while
// a live deployment is still in flight. Registering must stay blocked from a
// terminal origin so late/duplicate registration callbacks cannot demote a
// reconciled target.
func TestAWSOrganizationRolloutTargetStateAdvances(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		want bool
	}{
		{"identity is a no-op advance", AWSOrganizationRolloutTargetConnected, AWSOrganizationRolloutTargetConnected, true},
		{"non-terminal advances anywhere", AWSOrganizationRolloutTargetValidating, AWSOrganizationRolloutTargetDeploying, true},
		{"terminal to terminal advances", AWSOrganizationRolloutTargetConnected, AWSOrganizationRolloutTargetFailed, true},
		{"connected reopens to deploying on active StackSet operation", AWSOrganizationRolloutTargetConnected, AWSOrganizationRolloutTargetDeploying, true},
		{"connected does not demote to registering (late callback)", AWSOrganizationRolloutTargetConnected, AWSOrganizationRolloutTargetRegistering, false},
		{"connected does not demote to validating (late callback)", AWSOrganizationRolloutTargetConnected, AWSOrganizationRolloutTargetValidating, false},
		{"failed reopens to deploying on redeploy", AWSOrganizationRolloutTargetFailed, AWSOrganizationRolloutTargetDeploying, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := awsOrganizationRolloutTargetStateAdvances(tc.from, tc.to)
			if got != tc.want {
				t.Fatalf("advances(%q, %q) = %v; want %v", tc.from, tc.to, got, tc.want)
			}
		})
	}
}

// TestAWSOrganizationRolloutCancelableOnLifecycleChange documents which
// statuses a connector disable/disconnect actually retires: completed must
// stay eligible for reconciliation so drift monitoring is preserved.
func TestAWSOrganizationRolloutCancelableOnLifecycleChange(t *testing.T) {
	cancelable := map[string]bool{
		AWSOrganizationRolloutStatusCreated:     true,
		AWSOrganizationRolloutStatusLaunching:   true,
		AWSOrganizationRolloutStatusInProgress:  true,
		AWSOrganizationRolloutStatusReconciling: true,
		AWSOrganizationRolloutStatusPartial:     true,
		AWSOrganizationRolloutStatusFailed:      true,
		AWSOrganizationRolloutStatusCompleted:   false,
		AWSOrganizationRolloutStatusExpired:     false,
		AWSOrganizationRolloutStatusCanceled:    false,
	}
	for status, want := range cancelable {
		got := awsOrganizationRolloutCancelableOnLifecycleChange(status)
		if got != want {
			t.Fatalf("cancelable(%q) = %v; want %v", status, got, want)
		}
	}
}
