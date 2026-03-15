#!/usr/bin/env python3
import sys

# This reads commits from stdin and rewrites author/committer
for line in sys.stdin:
    if line.startswith(b'author '):
        line = b'author Akash <akash06-cs@gmail.com>\n'
    if line.startswith(b'committer '):
        line = b'committer Akash <akash06-cs@gmail.com>\n'
    sys.stdout.buffer.write(line)
