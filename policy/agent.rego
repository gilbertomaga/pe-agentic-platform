package agent.policy

# What an agent is allowed to do.
#
# This is the guardrail layer, and it is deliberately the smallest and most readable file in the
# platform, because it is the one a client security lead will actually read.
#
# Precedence is forbidden, then human gated, then autonomous, then deny. An action that appears in
# no set is denied, with a reason. See docs/decisions.md D3.

import rego.v1

# Reversible, contained, no consequence that survives the run.
autonomous contains "read:repository"

autonomous contains "read:knowledge_base"

autonomous contains "run:tests"

autonomous contains "build:image"

autonomous contains "write:branch"

autonomous contains "open:pull_request"

# Not the agent's alone, whatever the deadline. Opening a pull request is autonomous; the
# merge is where the change enters the trunk, and a named human owns that.
human_gated contains "merge:main"

# Every environment, dev included. Dev is shared with other teams, so an unattended deploy
# breaks somebody else's work, not just the agent's own.
human_gated contains "deploy:dev"

human_gated contains "deploy:qa"

human_gated contains "deploy:uat"

human_gated contains "deploy:production"

# Not a gate. These do not happen at all.
forbidden contains "read:customer_data"

forbidden contains "write:secret"

# An agent that can edit its own policy has no policy, and the trail would record that as normal.
forbidden contains "write:policy"

action := sprintf("%s:%s", [input.verb, input.target])

default decision := {
	"outcome": "deny",
	"reason": "not listed in any policy set, and unlisted actions are denied by default",
}

decision := {
	"outcome": "forbidden",
	"reason": sprintf("%s is never an agent's to take, whatever the deadline", [action]),
} if action in forbidden

decision := {
	"outcome": "human_gated",
	"reason": sprintf("%s requires a named human approver", [action]),
} if {
	action in human_gated
	not action in forbidden
}

decision := {
	"outcome": "allow",
	"reason": sprintf("%s is permitted inside the sandbox", [action]),
} if {
	action in autonomous
	not action in human_gated
	not action in forbidden
}
