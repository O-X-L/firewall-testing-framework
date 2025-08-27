from sys import stdout
from os import environ

COLOR_OK = '\x1b[1;32m'
COLOR_WARN = '\x1b[1;33m'
COLOR_INFO = '\x1b[1;34m'
COLOR_ERROR = '\x1b[1;31m'
COLOR_DEBUG = '\x1b[35m'
RESET_STYLE = '\x1b[0m'


def _log(label: str, msg: str, color: str, symbol: str):
    stdout.write(
        color + symbol + ' ' + label.upper() + ': ' + msg + RESET_STYLE + '\n',
    )


def log_debug(label: str, msg: str):
    if 'DEBUG' in environ:
        _log(label='DEBUG ' + label, msg=msg, color=COLOR_DEBUG, symbol='🛈')


def log_ok(label: str, msg: str):
    _log(label=label, msg=msg, color=COLOR_OK, symbol=' ✓')


def log_info(label: str, msg: str):
    _log(label=label, msg=msg, color=COLOR_INFO, symbol='🛈')


def log_warn(label: str, msg: str):
    _log(label=label, msg=msg, color=COLOR_WARN, symbol='⚠')


def log_error(label: str, msg: str):
    _log(label=label, msg=msg, color=COLOR_ERROR, symbol=' ✖')
