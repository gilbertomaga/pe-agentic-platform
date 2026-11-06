package agent.policy_test

# Guardrail tests. The policy is only a control if its behaviour is asserted, and the case that
# matters most is the one nobody wrote a rule for.

import data.agent.policy
import rego.v1

test_sandbox_work_is_allowed if {
	policy.decision.outcome == "allow" with input as {"verb": "read", "target": "repository"}
	policy.decision.outcome == "allow" with input as {"verb": "run", "target": "tests"}
	policy.decision.outcome == "allow" with input as {"verb": "build", "target": "image"}
}

test_opening_a_pull_request_is_autonomous if {
	# Proposing a change asks for review rather than avoiding it.
	policy.decision.outcome == "allow" with input as {"verb": "open", "target": "pull_request"}
}

test_merging_is_not if {
	policy.decision.outcome == "human_gated" with input as {"verb": "merge", "target": "main"}
}

test_every_deploy_needs_a_human_including_dev if {
	policy.decision.outcome == "human_gated" with input as {"verb": "deploy", "target": "dev"}
	policy.decision.outcome == "human_gated" with input as {"verb": "deploy", "target": "qa"}
	policy.decision.outcome == "human_gated" with input as {"verb": "deploy", "target": "uat"}
	policy.decision.outcome == "human_gated" with input as {"verb": "deploy", "target": "production"}
}

test_customer_data_is_not_gated_it_is_forbidden if {
	# A gate implies somebody could say yes. Nobody here can.
	policy.decision.outcome == "forbidden" with input as {"verb": "read", "target": "customer_data"}
}

test_an_agent_cannot_edit_its_own_policy if {
	policy.decision.outcome == "forbidden" with input as {"verb": "write", "target": "policy"}
}

test_an_unlisted_action_is_denied if {
	# Nobody wrote a rule for deleting the ticket store. That is not permission.
	policy.decision.outcome == "deny" with input as {"verb": "delete", "target": "ticket_store"}
}

test_a_plausible_but_unlisted_action_is_still_denied if {
	# "export" looks harmless next to "read". It is not in the allowed set.
	policy.decision.outcome == "deny" with input as {"verb": "export", "target": "customer_list"}
}

test_every_decision_carries_a_reason if {
	# An unexplained denial is indistinguishable from a bug, and engineers route around
	# things they think are bugs.
	count(policy.decision.reason) > 0 with input as {"verb": "read", "target": "repository"}
	count(policy.decision.reason) > 0 with input as {"verb": "deploy", "target": "production"}
	count(policy.decision.reason) > 0 with input as {"verb": "write", "target": "policy"}
	count(policy.decision.reason) > 0 with input as {"verb": "delete", "target": "ticket_store"}
}
