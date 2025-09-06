RULE_ACTIONS = ['accept', 'drop', 'reject', 'continue', 'jump', 'return', 'goto', 'dnat', 'snat', 'masquerade']
MAIN_ENTRIES = ['table', 'chain', 'rule', 'counter', 'limit', 'set']
SUB_ENTRIES = ['metainfo', 'map', 'element', 'flowtable', 'quota', 'ct helper', 'ct timeout', 'ct expectation']
VALID_ENTRIES = MAIN_ENTRIES.copy()
VALID_ENTRIES.extend(SUB_ENTRIES)

# todo: inform users via docs that these statements will be ignored
IGNORE_RULE_EXPRESSIONS = ['log', 'comment', 'limit', 'set', 'vmap', 'counter', 'xt']
IGNORE_LEFT = ['&']
