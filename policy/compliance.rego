package compliance.policy

# The client's compliance controls, as policy.
#
# agent.rego says what an agent may do. This says what has to be true about the people around the
# action, which is the part no action list can express and the part every control framework has
# an opinion about.
#
# It is a separate file and a separate package on purpose. agent.rego is the platform's own
# guardrail and changes when the platform changes. This one belongs to the client: when their
# control set changes, this is the file that moves, and nothing in the runtime has to.
#
# Precedence is the same reflex as agent.rego. Anything this cannot evaluate is refused rather
# than assumed, because a compliance control that fails open is a control that reports itself as
# held on exactly the runs where it was not.

import rego.v1

# Read once, with a default, and compared without case or surrounding space. Two spellings of one
# person are one person. This is not identity resolution and does not pretend to be: it catches
# the careless case, and anybody determined to approve their own work can still do it with a
# second account. That is a joiners and leavers problem and not something a policy file reaches.
requester := lower(trim_space(object.get(input, "requested_by", "")))

approver := lower(trim_space(object.get(input, "approver", "")))

# Which decisions this has anything to say about. An autonomous action has no approver and no
# separation to enforce, so there is nothing here for it.
needs_a_person if input.outcome == "human_gated"

default decision := {
	"outcome": "comply",
	"reason": "no human in this action, so there is no separation to enforce",
}

# An action that needed a human, where nobody is recorded as having asked for it. The separation
# cannot be checked at all, which is not the same as it holding. Refuse rather than record a
# control as met on the strength of a missing field.
decision := {
	"outcome": "refuse",
	"control": "segregation of duties",
	"reason": "this action needs a human and nobody is recorded as having requested it, so no separation can be shown",
} if {
	needs_a_person
	count(requester) == 0
}

# Here because the control statement is "a named approver who is not the requester", and half a
# statement in a policy file is how a control gets read as narrower than it is. The runtime does
# not reach this rule: it halts a gated action with no approver earlier, with a quieter outcome
# and no alert, because waiting for an approver is the gate working rather than somebody trying
# to get around it. That earlier halt has its own test.
decision := {
	"outcome": "refuse",
	"control": "segregation of duties",
	"reason": "this action needs a human and nobody is named as approving it",
} if {
	needs_a_person
	count(requester) > 0
	count(approver) == 0
}

# The control itself. One person asking and the same person approving is one person deciding,
# whatever the record says, and it is the oldest finding in any audit of any approval workflow.
decision := {
	"outcome": "refuse",
	"control": "segregation of duties",
	"reason": sprintf("%s cannot approve an action they requested", [approver]),
} if {
	needs_a_person
	count(requester) > 0
	count(approver) > 0
	requester == approver
}

decision := {
	"outcome": "comply",
	"control": "segregation of duties",
	"reason": sprintf("requested by %s, approved by %s", [requester, approver]),
} if {
	needs_a_person
	count(requester) > 0
	count(approver) > 0
	requester != approver
}
