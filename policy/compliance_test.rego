package compliance.policy_test

import data.compliance.policy
import rego.v1

# The control holds: two different people.
test_a_request_and_a_different_approver_complies if {
	out := policy.decision with input as {
		"outcome": "human_gated",
		"requested_by": "a.silva",
		"approver": "r.okonkwo",
	}
	out.outcome == "comply"
}

# The control, and the oldest finding in any audit of any approval workflow.
test_nobody_approves_their_own_request if {
	out := policy.decision with input as {
		"outcome": "human_gated",
		"requested_by": "a.silva",
		"approver": "a.silva",
	}
	out.outcome == "refuse"
	out.control == "segregation of duties"
}

# Two spellings of one person are one person, at least for the careless case.
test_case_and_spacing_do_not_make_a_second_person if {
	out := policy.decision with input as {
		"outcome": "human_gated",
		"requested_by": "A.Silva ",
		"approver": " a.silva",
	}
	out.outcome == "refuse"
}

# Not checkable is not the same as held.
test_an_unnamed_requester_is_refused_rather_than_assumed if {
	out := policy.decision with input as {
		"outcome": "human_gated",
		"approver": "r.okonkwo",
	}
	out.outcome == "refuse"
}

test_an_empty_requester_is_not_a_name if {
	out := policy.decision with input as {
		"outcome": "human_gated",
		"requested_by": "   ",
		"approver": "r.okonkwo",
	}
	out.outcome == "refuse"
}

test_an_unnamed_approver_is_refused if {
	out := policy.decision with input as {
		"outcome": "human_gated",
		"requested_by": "a.silva",
	}
	out.outcome == "refuse"
}

# An autonomous action has no human in it, so there is nothing to separate.
test_an_autonomous_action_has_no_separation_to_enforce if {
	out := policy.decision with input as {
		"outcome": "allow",
		"verb": "read",
		"target": "repository",
	}
	out.outcome == "comply"
}

# Whatever else is going on, an action nobody gated is not this file's business.
test_a_denied_action_is_not_this_policys_concern if {
	out := policy.decision with input as {
		"outcome": "deny",
		"requested_by": "a.silva",
		"approver": "a.silva",
	}
	out.outcome == "comply"
}
