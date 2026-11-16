#!/usr/bin/env python3
"""Refresh the two owned Wi-Fi inventories from reviewed Kbuild selections."""
import ast
import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
import subprocess


TREES = {'net/mac80211': 'mac80211', 'net/wireless': 'cfg80211'}
# PM and OF are enabled by the arm64/GKI defaults. The remaining values match
# the Onyx fragment; this evaluator deliberately rejects new configuration cases.
CONFIG = {
    'CONFIG_PM': 'y', 'CONFIG_OF': 'y',
    'CONFIG_MAC80211': 'm', 'CONFIG_MAC80211_LEDS': 'y',
    'CONFIG_MAC80211_RC_MINSTREL': 'y', 'CONFIG_MAC80211_DEBUGFS': '',
    'CONFIG_MAC80211_MESH': '', 'CONFIG_CFG80211': 'm',
    'CONFIG_CFG80211_DEBUGFS': '', 'CONFIG_CFG80211_WEXT': '',
    'CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS': 'y',
    'CONFIG_CFG80211_EXTRA_REGDB_KEYDIR': '',
}
REQUIRED_CONFIG = {
    'CONFIG_MAC80211', 'CONFIG_MAC80211_LEDS', 'CONFIG_MAC80211_RC_MINSTREL',
    'CONFIG_MAC80211_DEBUGFS', 'CONFIG_MAC80211_MESH', 'CONFIG_CFG80211',
    'CONFIG_CFG80211_USE_KERNEL_REGDB_KEYS',
}
# Exact logical target/recipe blocks from pristine Common 468a9355f579.
# BUILD.bazel owns an equivalent certificate generator, so changed upstream
# generation semantics require review instead of being silently ignored.
CERTIFICATE_RULES = {
    '$(obj)/shipped-certs.c: $(sort $(wildcard $(src)/certs/*.hex))':
        '97328e0e05c7f279ed3e6ebf2d7b697dacc0a2521bbd4a9067c76999dd9b448f',
    '$(obj)/extra-certs.c: $(CONFIG_CFG80211_EXTRA_REGDB_KEYDIR) '
    '$(sort $(wildcard $(CONFIG_CFG80211_EXTRA_REGDB_KEYDIR)/*.x509))':
        '48a234417d11810de4c84aafc41d1dca6267ade8703b4ffb61f672c4c576262e',
}


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def safe_name(name):
    if not isinstance(name, str):
        raise ValueError('Import path must be a string')
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or str(path) != name
            or '..' in path.parts or '.git' in path.parts
            or not re.fullmatch(r'[A-Za-z0-9_.,/+\-]+', name)):
        raise ValueError('Unsafe import path: ' + name)
    return name


def owned(name):
    return any(name.startswith(tree + '/') for tree in TREES)


def configuration(fragment):
    declared = {}
    for line in fragment.splitlines():
        match = re.fullmatch(r'(CONFIG_[A-Z0-9_]+)=(.*)', line)
        disabled = re.fullmatch(r'# (CONFIG_[A-Z0-9_]+) is not set', line)
        if match:
            name, value = match.groups()
            value = '' if value == 'n' else value
        elif disabled:
            name, value = disabled.group(1), ''
        else:
            continue
        if name in declared:
            raise ValueError('Duplicate platform configuration: ' + name)
        declared[name] = value
    for name in REQUIRED_CONFIG:
        if name not in declared:
            raise ValueError('Missing reviewed Wi-Fi configuration: ' + name)
    for name, expected in CONFIG.items():
        if name in declared and declared[name] != expected:
            raise ValueError('Unsupported Wi-Fi configuration: ' + name)
    return CONFIG


def logical_lines(text):
    pending = ''
    for line in text.splitlines():
        pending += line[:-1] + ' ' if line.endswith('\\') else line
        if line.endswith('\\'):
            continue
        yield pending
        pending = ''
    if pending:
        raise ValueError('Unterminated Kbuild continuation')


def object_lines(text, module):
    lines, seen, index = list(logical_lines(text)), set(), 0
    while index < len(lines):
        raw = lines[index]
        index += 1
        if raw.startswith('\t'):
            raise ValueError('Recipe outside a reviewed Wi-Fi certificate target')
        target = ' '.join(raw.split())
        if target not in CERTIFICATE_RULES:
            yield raw
            continue
        if module != 'cfg80211' or target in seen:
            raise ValueError('Unexpected Wi-Fi certificate target: ' + target)
        block = [raw]
        while index < len(lines) and lines[index].startswith('\t'):
            block.append(lines[index])
            index += 1
        if hashlib.sha256('\n'.join(block).encode()).hexdigest() != CERTIFICATE_RULES[target]:
            raise ValueError('Wi-Fi certificate recipe differs from the reviewed generator')
        seen.add(target)
    if module == 'cfg80211' and seen != set(CERTIFICATE_RULES):
        raise ValueError('Missing reviewed Wi-Fi certificate generator')


def objects(text, module, config):
    """Evaluate only the object-list syntax used by these two reviewed recipes."""
    values, simple, conditions = {}, set(), []
    root_seen = False
    prefixes = {module}
    if module == 'mac80211':
        prefixes.add('rc80211_minstrel')

    def expand(tokens, visiting=()):
        result = []
        for token in tokens:
            reference = re.fullmatch(r'\$\(([a-zA-Z0-9_-]+)\)', token)
            if reference:
                name = reference.group(1)
                if name not in values or name in visiting:
                    raise ValueError('Unknown or recursive Kbuild object variable: ' + name)
                result.extend(expand(values[name], (*visiting, name)))
            elif re.fullmatch(r'[A-Za-z0-9_-]+\.o', token):
                result.append(token)
            else:
                raise ValueError('Unsupported Kbuild object expression: ' + token)
        return result

    for raw in object_lines(text, module):
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if line == 'ifneq ($(CONFIG_CFG80211_EXTRA_REGDB_KEYDIR),)':
            conditions.append(bool(config['CONFIG_CFG80211_EXTRA_REGDB_KEYDIR']))
            continue
        if line == 'endif':
            if not conditions:
                raise ValueError('Unmatched Kbuild endif')
            conditions.pop()
            continue
        assignment = re.fullmatch(r'(\S+)\s*(:=|\+=)\s*(.*)', line)
        if not assignment:
            raise ValueError('Unsupported Wi-Fi Kbuild statement: ' + line)
        name, operation, rhs = assignment.groups()
        if name.startswith('obj-'):
            if line == 'obj-$(CONFIG_' + module.upper() + ') += ' + module + '.o':
                if root_seen:
                    raise ValueError('Duplicate Wi-Fi module declaration')
                root_seen = True
            elif line not in (
                    'obj-y += tests/', 'obj-$(CONFIG_WEXT_CORE) += wext-core.o',
                    'obj-$(CONFIG_WEXT_PROC) += wext-proc.o',
                    'obj-$(CONFIG_WEXT_PRIV) += wext-priv.o'):
                raise ValueError('Unsupported Wi-Fi Kbuild module: ' + line)
            continue
        if name in ('CFLAGS_trace.o', 'ccflags-y', 'clean-files'):
            if line not in ('CFLAGS_trace.o := -I$(src)', 'ccflags-y += -DDEBUG',
                            'clean-files += shipped-certs.c extra-certs.c'):
                raise ValueError('Unsupported Wi-Fi Kbuild flags: ' + line)
            continue
        match = re.fullmatch(r'([a-zA-Z0-9_]+)-(y|\$\((CONFIG_[A-Z0-9_]+)\))', name)
        if not match or match.group(1) not in prefixes:
            raise ValueError('Unsupported Wi-Fi Kbuild variable: ' + name)
        prefix, suffix, option = match.groups()
        if option and option not in config:
            raise ValueError('Unknown Wi-Fi Kbuild configuration: ' + option)
        tokens = rhs.split()
        # Validate even disabled branches rather than silently ignoring syntax.
        expanded = expand(tokens)
        if not all(conditions) or (option and config[option] != 'y'):
            continue
        name = prefix + '-y'
        if operation == ':=':
            values[name] = expanded
            simple.add(name)
        else:
            values.setdefault(name, []).extend(expanded if name in simple else tokens)
    if conditions or not root_seen:
        raise ValueError('Incomplete Wi-Fi Kbuild recipe')
    result = expand(values.get(module + '-y', []))
    if not result or len(set(result)) != len(result):
        raise ValueError('Empty or duplicate Wi-Fi Kbuild object selection')
    return result


def tree_blobs(repo, revision, tree):
    blobs = {}
    for entry in git(repo, 'ls-tree', '-rz', revision, '--', tree).split(b'\0'):
        if not entry:
            continue
        metadata, name = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        name = safe_name(name.decode())
        if (not name.startswith(tree + '/') or name in blobs
                or mode not in ('100644', '100755') or kind != 'blob'
                or not re.fullmatch(r'[0-9a-f]{40}', blob)):
            raise ValueError('Invalid regular Wi-Fi source: ' + name)
        blobs[name] = blob
    for required in ('Makefile', 'Kconfig'):
        if tree + '/' + required not in blobs:
            raise ValueError('Incomplete Wi-Fi source tree: ' + tree)
    return blobs


def literal(build, target, attribute, replacement=None):
    stanzas = [match for match in re.finditer(r'(?ms)^\w+\(\n.*?^\)', build)
               if re.search(r'^    name = "' + re.escape(target) + r'",$', match.group(), re.M)]
    if len(stanzas) != 1:
        raise ValueError('Expected one Wi-Fi BUILD target: ' + target)
    stanza = stanzas[0]
    matches = list(re.finditer(r'(?m)^    ' + attribute + r' = (\[[^\n]*\]),$', stanza.group()))
    if len(matches) != 1:
        raise ValueError('Expected one literal Wi-Fi BUILD list: ' + target + '/' + attribute)
    match = matches[0]
    values = ast.literal_eval(match.group(1))
    if (not isinstance(values, list) or any(not isinstance(value, str) for value in values)
            or len(set(values)) != len(values)):
        raise ValueError('Invalid Wi-Fi BUILD list: ' + target)
    if replacement is None:
        return values
    start, end = stanza.start() + match.start(1), stanza.start() + match.end(1)
    return build[:start] + json.dumps(replacement) + build[end:]


def refresh(repo, revision, imports, build, fragment):
    """Return validated prospective imports/BUILD; never modify recipe files."""
    if not any(source.get('project') == 'common' and owned(source.get('path', ''))
               for source in imports):
        return imports, build
    if build is None or fragment is None:
        raise ValueError('Wi-Fi inventory refresh requires BUILD.bazel and platform_defconfig')
    config = configuration(fragment)
    old = {}
    for source in imports:
        name = safe_name(source['path'])
        if name in old:
            raise ValueError('Duplicate import target: ' + name)
        old[name] = source
        if owned(name) and source['project'] != 'common':
            raise ValueError('Wi-Fi source collides with a pinned baseline import: ' + name)
        if owned(name) and set(source) != {'project', 'revision', 'path', 'blob'}:
            raise ValueError('Unexpected Wi-Fi import provenance: ' + name)
    selected, blobs = [], {}
    for tree, module in TREES.items():
        inventory = tree_blobs(repo, revision, tree)
        blobs.update(inventory)
        makefile = git(repo, 'cat-file', 'blob', inventory[tree + '/Makefile']).decode()
        sources = []
        for item in objects(makefile, module, config):
            name = tree + '/' + item[:-2] + '.c'
            if name == 'net/wireless/shipped-certs.c':
                sources.append(':' + name)
            elif name in inventory:
                sources.append(name)
            else:
                raise ValueError('Selected Wi-Fi source is missing: ' + name)
        headers = sorted(name for name in inventory
                         if name.startswith(tree + '/') and '/' not in name[len(tree) + 1:]
                         and name.endswith('.h'))
        header_target = 'mac80211_headers' if module == 'mac80211' else 'wireless_framework_headers'
        previous = literal(build, header_target, 'hdrs')
        if any(not name.startswith(tree + '/') or not name.endswith('.h') for name in previous):
            raise ValueError('Wi-Fi header target contains unowned inputs')
        old_inputs = {name for name in old if name.startswith(tree + '/')}
        old_headers = {name for name in old_inputs if name.endswith('.h')}
        if set(previous) != old_headers:
            raise ValueError('Wi-Fi header BUILD list differs from the pinned inventory')
        ordered_headers = [name for name in previous if name in headers]
        ordered_headers += [name for name in headers if name not in previous]
        build = literal(build, header_target, 'hdrs', ordered_headers)
        previous_sources = literal(build, module, 'srcs')
        if any(not name.removeprefix(':').startswith(tree + '/') for name in previous_sources):
            raise ValueError('Wi-Fi module target contains unowned inputs')
        generated = {':net/wireless/shipped-certs.c'} if module == 'cfg80211' else set()
        old_sources = {name for name in old_inputs if name.endswith('.c')}
        if set(previous_sources) != old_sources | generated:
            raise ValueError('Wi-Fi source BUILD list differs from the pinned inventory')
        build = literal(build, module, 'srcs', sources)
        selected.extend(name for name in sources if not name.startswith(':'))
        selected.extend(headers)
        if module == 'cfg80211':
            certs = sorted(name for name in inventory
                           if re.fullmatch(re.escape(tree) + r'/certs/[^/]+\.hex', name))
            if not certs:
                raise ValueError('Wi-Fi regulatory certificate inventory is empty')
            old_certs = {name for name in old_inputs if name.endswith('.hex')}
            if set(literal(build, 'cfg80211_regdb_certs', 'srcs')) != old_certs:
                raise ValueError('Wi-Fi certificate BUILD list differs from the pinned inventory')
            build = literal(build, 'cfg80211_regdb_certs', 'srcs', certs)
            selected.extend(certs)
        else:
            old_certs = set()
        if old_inputs != old_headers | old_sources | old_certs | {
                tree + '/Makefile', tree + '/Kconfig'}:
            raise ValueError('Unexpected input in the owned Wi-Fi inventory')
        selected.extend(tree + '/' + name for name in ('Makefile', 'Kconfig'))
    if len(set(selected)) != len(selected):
        raise ValueError('Duplicate selected Wi-Fi input')
    wanted = set(selected)
    result = []
    for source in imports:
        if not owned(source['path']):
            result.append(copy.deepcopy(source))
        elif source['path'] in wanted:
            updated = copy.deepcopy(source)
            updated.update(revision=revision, blob=blobs[source['path']])
            result.append(updated)
    for name in selected:
        if name not in old:
            result.append({'project': 'common', 'revision': revision, 'path': name, 'blob': blobs[name]})
    return result, build
