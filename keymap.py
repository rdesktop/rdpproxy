#!/usr/bin/python

import os
import string
import re

class keymap:
    mapfind = re.compile("([a-zA-Z0-9])*? 0x([0-9a-z]{1,2})(.*)")
    
    def read_keymap(self, path, name):
        keys = {}
        km = open(os.path.join(path, name), 'r')
        for line in km.xreadlines():
            if '#' == line[0] or '\n' == line[0]:
                continue

            line = line.strip()

            if "include " == line[:8]:
                keys.update(self.read_keymap(path, line[8:].strip()))
                continue
            elif "map " == line[:4]:
                self.map = string.atol(line[4:], 16)
                continue

            elif "enable_compose" == line[:15]:
                self.enable_compose = 1
                continue
            else:
                mo = self.mapfind.search(line)
                (key, code, rest) = mo.groups()

                keys[string.atoi(code, 16)] = "%s / %s" % (key, rest)

        return keys
            

    def __init__(self, path, name="common"):
        self.path = path
        self.name = name
        self.map = 0x407
        self.enable_compose = 0
        self.keys = self.read_keymap(path, name)

    def __getitem__(self, key):
        return self.keys.get(key, "Unknown")
