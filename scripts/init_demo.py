"""Create an isolated local demo; never read or overwrite real configuration."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo.assets import initialize

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parents[1] / ".demo")
    arguments = parser.parse_args()
    print(f"Local demo assets ready: {initialize(arguments.directory)}")
