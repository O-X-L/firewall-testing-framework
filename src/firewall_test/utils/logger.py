from sys import stdout
from os import environ

from config import ENV_VERBOSITY, ENV_DEBUG, VERBOSITY_DEBUG, VERBOSITY_DEFAULT, ENV_LOG_COLOR

COLOR_OK = '\x1b[1;32m'
COLOR_WARN = '\x1b[1;33m'
COLOR_INFO = '\x1b[1;34m'
COLOR_ERROR = '\x1b[1;31m'
COLOR_DEBUG = '\x1b[35m'
RESET_STYLE = '\x1b[0m'


def _build_msg_by_verbosity(v0: (str, None), v1: (str, None), v2: (str, None), v3: (str, None), final: bool) -> str:
    verbosity = environ.get(ENV_VERBOSITY, VERBOSITY_DEFAULT)
    if final or ENV_DEBUG in environ:
        # always output it - ignore user-provided verbosity (end result)
        verbosity = VERBOSITY_DEBUG

    msg = ''

    for p in {
        VERBOSITY_DEBUG: [v0, v1, v2, v3],
        '3': [v0, v1, v2],
        '2': [v0, v1],
        '1': [v0],
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
        v0: (str, None), v1: (str, None), v2: (str, None), v3: (str, None), final: bool,
):
    _log(
        label=label,
        msg=_build_msg_by_verbosity(v0, v1, v2, v3, final=final),
        color=color,
        symbol=symbol,
    )


def log_ok(label: str, v0: str = None, v1: str = None, v2: str = None, v3: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_OK,
        symbol='✓',
        v0=v0,
        v1=v1,
        v2=v2,
        v3=v3,
        final=final,
    )


def log_info(label: str, v0: str = None, v1: str = None, v2: str = None, v3: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_INFO,
        symbol='🛈',
        v0=v0,
        v1=v1,
        v2=v2,
        v3=v3,
        final=final,
    )


def log_warn(label: str, v0: str = None, v1: str = None, v2: str = None, v3: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_WARN,
        symbol='⚠',
        v0=v0,
        v1=v1,
        v2=v2,
        v3=v3,
        final=final,
    )

def log_error(label: str, v0: str = None, v1: str = None, v2: str = None, v3: str = None, final: bool = False):
    _log_with_verbosity(
        label=label,
        color=COLOR_ERROR,
        symbol='✖',
        v0=v0,
        v1=v1,
        v2=v2,
        v3=v3,
        final=final,
    )
