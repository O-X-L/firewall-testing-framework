from pathlib import Path

_dir = Path(__file__).parent.parent.parent / 'testdata'
TESTDATA_FILE_ROUTES = _dir / 'plugin_translate_linux_routes.json'
TESTDATA_FILE_ROUTE_RULES = _dir / 'plugin_translate_linux_route-rules.json'
TESTDATA_FILE_NIS = _dir / 'plugin_translate_linux_interfaces.json'
