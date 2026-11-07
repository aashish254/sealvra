"""Entry point: ``python3 -m sealvra`` from the build root."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
