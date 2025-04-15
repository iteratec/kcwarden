import argparse
from pathlib import Path


def is_dir(val: str) -> Path:
    """Converts a string to a Path object.

    Args:
        val: The parameter's value to check.

    Returns:
        The value as Path.

    Raises:
        argparse.ArgumentTypeError: If the value is not a directory.
    """
    path = Path(val)
    if not path.is_dir():
        raise argparse.ArgumentTypeError(f"{val} is not a directory")
    return path


def is_a_file(value: str) -> Path:
    """Checks whether the given string is a path to an existing file and if so, returns it as Path.

    Args:
        value: The string to process.

    Returns:
        The corresponding Path instance.
    """
    path = Path(value)
    if not path.exists() or not path.is_file():
        raise argparse.ArgumentTypeError(f"{value} is not a file")
    return path.absolute()
