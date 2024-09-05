import argparse
from pathlib import Path


def is_dir(val: str) -> Path:
    """
    Converts a string to a Path object.

    :param val: The parameter's value to check.
    :return: The value as Path.
    :raises argparse.ArgumentTypeError: If the value is not a directory.
    """
    path = Path(val)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"{val} is not a directory")
    return path
