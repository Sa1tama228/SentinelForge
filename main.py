"""SentinelForge entry point."""
import logging

from sentinelforge.ui import shell

logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    shell.run()
