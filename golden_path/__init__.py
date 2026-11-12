"""Guard the Python version before anything imports tomllib.

A stock macOS has no `python` at all and its `python3` is 3.9, where the first thing this package
touches is `import tomllib` and the newcomer gets a ModuleNotFoundError with no hint of what to do.
A golden path whose first step is an unexplained traceback is not a golden path. Found by somebody
who had never seen this repository, which is the only way this kind of thing is ever found.
"""
import sys

if sys.version_info < (3, 11):
    sys.exit(
        "This platform needs Python 3.11 or newer. You are running "
        "{}.{}.{}.\n"
        "The system python3 on macOS is 3.9, which has no tomllib. Install a newer one, for\n"
        "example `brew install python@3.12`, then run the command with python3.12.".format(
            sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    )
