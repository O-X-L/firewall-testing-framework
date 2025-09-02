from pathlib import Path

from plugins.system.config import SYSTEM_MAPPING, COMPONENT_MAPPING


def load(
        system: str,
        file_interfaces: (str, Path),
        file_ruleset: (str, Path),
        file_routes: (str, Path),
        file_route_rules: (str, Path) = None,
) -> dict:
    system = SYSTEM_MAPPING.get(system, None)
    if system is None:
        raise ValueError(f"Got invalid system: {system} - supported ones: {list(SYSTEM_MAPPING.keys())}")

    if system.ROUTE_STATIC_RULES and file_route_rules is None:
        raise ValueError('Required Route-Rules not supplied!')

    loaded = {
        'system': system,
    }
    for kind, file in {
        'nis': file_interfaces,
        'routes': file_routes,
        'route_rules': file_route_rules,
        'ruleset': file_ruleset,
    }.items():
        if file is None:
            continue

        if not Path(file).is_file():
            raise FileNotFoundError(f"Supplied {kind}-file does not exist: {file}")

        with open(file, 'r', encoding='utf-8') as f:
            loaded[kind] = COMPONENT_MAPPING[system][kind](f.read()).get()

    return loaded
