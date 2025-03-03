"""
Command Line Interface Entry Point

This module serves as the entry point for the command line interface of the
Certificate Authority package. It imports and runs the CLI application,
allowing users to interact with the CA functionality through the command line.

Example:
    $ python -m CA init --common-name "My Root CA"
    $ python -m CA issue --type server --common-name "example.com"
"""

import asyncio

from .cli import main

if __name__ == "__main__":
    asyncio.run(main())
