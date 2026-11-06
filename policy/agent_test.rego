package agent.policy_test

# Guardrail tests. The policy is only a control if its behaviour is asserted, and the case that
# matters most is the one nobody wrote a rule for.

import data.agent.policy
import rego.v1

outcome(verb, target) := policy.decision.outcome with input as {"verb": verb, "target": target}

reason(verb, target) := policy.decision.reason with input as {"verb": verb, "target": target}

test_sandbox_work_is_allowed if {
	outcome("read", "repository") == "allow"
	outcome("run", "tests") == "allow"
	outcome("build", "image") == "allow"
}

test_opening_a_pull_request_is_autonomous if {
	# Proposing a change asks for review rather than avoiding it.
	outcome("open", "pull_request") == "allow"
}

test_merging_is_not if {
	outcome("merge", "main") == "human_gated"
}

test_every_deploy_needs_a_human_including_dev if {
	outcome("deploy", "dev") == "human_gated"
	outcome("deploy", "qa") == "human_gated"
	outcome("deploy", "uat") == "human_gated"
	outcome("deploy", "production") == "human_gated"
}

test_customer_data_is_not_gated_it_is_forbidden if {
	# A gate implies somebody could say yes. Nobody here can.
	outcome("read", "customer_data") == "forbidden"
}

test_an_agent_cannot_edit_its_own_policy if {
	outcome("write", "policy") == "forbidden"
}

test_an_unlisted_action_is_denied if {
	# Nobody wrote a rule for deleting the ticket store. That is not permission.
	outcome("delete", "ticket_store") == "deny"
}

test_a_plausible_but_unlisted_action_is_still_denied if {
	# "export" looks harmless next to "read". It is not in the allowed set.
	outcome("export", "customer_list") == "deny"
}

test_every_decision_carries_a_reason if {
	# An unexplained denial is indistinguishable from a bug, and engineers route around
	# things they think are bugs.
	count(reason("read", "repository")) > 0
	count(reason("deploy", "production")) > 0
	count(reason("write", "policy")) > 0
	count(reason("delete", "ticket_store")) > 0
}
