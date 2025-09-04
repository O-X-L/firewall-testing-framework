from abc import ABC


class RuleAction(ABC):
    N = 'Abstract Rule-Action'


class RuleActionAccept(RuleAction):
    N = 'accept'


class RuleActionDrop(RuleAction):
    N = 'drop'


class RuleActionReject(RuleAction):
    N = 'reject'


class RuleActionToChain(RuleAction):
    N = 'Abstract Rule-Action To-Chain'


class RuleActionJump(RuleActionToChain):
    N = 'jump'


class RuleActionGoTo(RuleActionToChain):
    N = 'goto'


class RuleActionContinue(RuleActionToChain):
    N = 'continue'


RULE_ACTIONS = [
    RuleActionAccept, RuleActionDrop, RuleActionReject,
    RuleActionJump, RuleActionGoTo, RuleActionContinue,
]
