from sys import stdout
from os import environ

from config import ENV_VERBOSITY, ENV_DEBUG, VERBOSITY_DEBUG, VERBOSITY_DEFAULT, ENV_LOG_COLOR

COLOR_OK = '\x1b[1;32m'
COLOR_WARN = '\x1b[1;33m'
COLOR_INFO = '\x1b[1;34m'
COLOR_ERROR = '\x1b[1;31m'
COLOR_DEBUG = '\x1b[35m'
RESET_STYLE = '\x1b[0m'

LOG_MAX_CHAR_RULE_MATCHES = 500 if ENV_DEBUG not in environ else 1_500


def _build_msg_by_verbosity(v1: (str, None), v2: (str, None), v3: (str, None), v4: (str, None), final: bool) -> str:
    verbosity = environ.get(ENV_VERBOSITY, VERBOSITY_DEFAULT)
    if final or ENV_DEBUG in environ:
        # always output it - ignore user-provided verbosity (end result)
        verbosity = VERBOSITY_DEBUG

    msg = ''

    for p in {
        VERBOSITY_DEBUG: [v1, v2, v3, v4],
        '3': [v1, v2, v3],
        '2': [v1, v2],
        '1': [v1],
    }.get(verbosity, []):
        if p is not None:
            msg += p

    return msg


def _log(label: str, msg: str, color: str, symbol: str):
    if msg.strip() == '':
        # minimal verbosity not met
        return

    if environ.get(ENV_LOG_COLOR, '1') == '0':
        stdout.write(
            symbol + ' ' + label.upper() + ': ' + msg + '\n',
        )

    else:
        stdout.write(
            color + symbol + ' ' + label.upper() + ': ' + msg + RESET_STYLE + '\n',
        )


def log_debug(label: str, msg: str):
    if ENV_DEBUG in environ or environ.get(ENV_VERBOSITY, VERBOSITY_DEFAULT) == VERBOSITY_DEBUG:
        _log(label='DEBUG ' + label, msg=msg, color=COLOR_DEBUG, symbol='🛈')


def _log_with_verbosity(
        label: str, color: str, symbol: str,
        v1: (str, None), v2: (str, None), v3: (str, None), v4: (str, None), final: bool,
):
    _log(
        label=label,
        msg=_build_msg_by_verbosity(v1, v2, v3, v4, final=final),
        color=color,
        symbol=symbol,
    )


def log_ok(label: str, v1: str = None, v2: str = None, v3: str = None, v4: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_OK,
        symbol='✓',
        v1=v1,
        v2=v2,
        v3=v3,
        v4=v4,
        final=final,
    )


def log_info(label: str, v1: str = None, v2: str = None, v3: str = None, v4: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_INFO,
        symbol='🛈',
        v1=v1,
        v2=v2,
        v3=v3,
        v4=v4,
        final=final,
    )


def log_warn(label: str, v1: str = None, v2: str = None, v3: str = None, v4: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_WARN,
        symbol='⚠',
        v1=v1,
        v2=v2,
        v3=v3,
        v4=v4,
        final=final,
    )

def log_error(label: str, v1: str = None, v2: str = None, v3: str = None, v4: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_ERROR,
        symbol='✖',
        v1=v1,
        v2=v2,
        v3=v3,
        v4=v4,
        final=final,
    )


def rule_repr(uid: (int, str), matches: any, cmt: str = None) -> str:
    # to make sure all plugins have a similar log-format

    if cmt is None:
        cmt = ''

    elif not cmt.startswith(' ') and cmt.strip() != '':
        cmt = f' "{cmt}"'

    if not isinstance(matches, str):
        matches = str(matches)

    if len(matches) > LOG_MAX_CHAR_RULE_MATCHES:
        matches = matches[:LOG_MAX_CHAR_RULE_MATCHES] + '...'

    return f"Rule: #{uid}{cmt}" + '\n' + f'             > Matches: {matches}' + '\n'
