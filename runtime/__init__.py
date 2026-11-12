"""Guard the Python version before anything imports tomllib. See golden_path/__init__.py."""
import sys

if sys.version_info < (3, 11):
    sys.exit(
        "This platform needs Python 3.11 or newer. You are running "
        "{}.{}.{}.\n"
        "The system python3 on macOS is 3.9, which has no tomllib. Install a newer one, for\n"
        "example `brew install python@3.12`, then run the command with python3.12.".format(
            sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    )
