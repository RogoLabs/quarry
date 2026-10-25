"""Quarry — local-first repository security audit.

Design invariant, from the review panel (docs/PLAN.md D6, Seat 5):

    No process holding a credential may (i) open a filesystem path derived from
    target content, (ii) execute a program named or configured by target content,
    or (iii) hold authority broader than the single action it performs.

Target bytes may *pass through* a credential-holding process as opaque data.
What is forbidden is a credential-holding process interpreting target content as
a path, a command, or a config.
"""
__version__ = "0.1.0"
