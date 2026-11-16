#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# udev-test-rules.py - dump the rule sets of upstream's test/test-udev.py
#
# 20261116 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: udev-test-rules.py SYSTEMD_SOURCE_DIR FAKE_SYSFS_PARENT
#
# Prints a JSON array, one object per rule set:
#   {"desc": ..., "rules": ..., "devices": [{"devpath": ..., "devnode": ...,
#    "exp_links": [...], "not_exp_links": [...], "exp_perms": ...}, ...]}
# The rule sets whose devices are generated from the fake sysfs (all block
# devices) are generated against FAKE_SYSFS_PARENT/sys.  pytest is not
# needed: a stub stands in for it.

import dataclasses
import importlib.util
import json
import sys
import types
from pathlib import Path


def stub_pytest() -> None:
    fake = types.ModuleType('pytest')
    fake.fixture = lambda *a, **k: (lambda f: f)
    fake.mark = types.SimpleNamespace(parametrize=lambda *a, **k: (lambda f: f))
    fake.skip = lambda *a, **k: None
    fake.raises = None
    fake.main = lambda *a, **k: 0
    sys.modules['pytest'] = fake


def main() -> int:
    source = Path(sys.argv[1])
    sysfs_parent = Path(sys.argv[2])
    stub_pytest()
    spec = importlib.util.spec_from_file_location('test_udev', source / 'test' / 'test-udev.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.UDEV_SYS = sysfs_parent / 'sys'
    out = []
    for rules in mod.RULES:
        rules.generate_devices()
        out.append({
            'desc': rules.desc,
            'rules': rules.rules,
            'devices': [dataclasses.asdict(d) for d in rules.devices],
        })
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
