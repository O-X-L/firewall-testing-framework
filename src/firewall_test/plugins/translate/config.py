from abc import ABC


class RuleAction(ABC):
    N = 'Abstract Rule-Action'


class RuleActionKindTerminal(RuleAction):
    N = 'Abstract Rule-Action Terminal'


class RuleActionKindTerminalKill(RuleActionKindTerminal):
    N = 'Abstract Rule-Action Terminal'


class RuleActionAccept(RuleActionKindTerminal):
    N = 'accept'


class RuleActionDrop(RuleActionKindTerminalKill):
    N = 'drop'


class RuleActionReject(RuleActionKindTerminalKill):
    N = 'reject'


class RuleActionKindToChain(RuleAction):
    N = 'Abstract Rule-Action To-Chain'


class RuleActionJump(RuleActionKindToChain):
    N = 'jump'


class RuleActionGoTo(RuleActionKindToChain):
    N = 'goto'


class RuleActionReturn(RuleActionKindTerminal):
    N = 'return'


class RuleActionContinue(RuleAction):
    N = 'continue'


class RuleActionKindNAT(RuleAction):
    N = 'Abstract Rule-Action NAT'


class RuleActionDNAT(RuleActionKindNAT):
    N = 'dnat'


class RuleActionSNAT(RuleActionKindNAT):
    N = 'snat'


RULE_ACTIONS = [
    RuleActionAccept, RuleActionDrop, RuleActionReject,
    RuleActionJump, RuleActionGoTo, RuleActionContinue, RuleActionReturn,
    RuleActionDNAT, RuleActionSNAT,
]
