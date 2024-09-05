import importlib
import inspect
import logging
import sys
from pathlib import Path
from typing import Type

from kcwarden.api import Auditor

logger = logging.getLogger(__name__)


def get_auditors(directory: Path) -> list[Type[Auditor]]:
    # Append the parent directory to the path thus we can import modules from there
    sys.path.append(str(directory.parent))

    auditors: list[Type[Auditor]] = []
    # List all Python files in the specified directory
    auditor_files = [f for f in directory.iterdir() if f.suffix == ".py" and f.name != "__init__.py"]

    # Iterate through the files and dynamically import the modules
    for file in auditor_files:
        module_name = file.stem  # Remove the .py extension
        module = importlib.import_module(f"{directory.name}.{module_name}")

        # Inspect the module to find classes that inherit from Auditor
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Auditor) and obj.__module__ == module.__name__:
                logger.debug(f"Found class {name} in {file} that inherits from {Auditor}")
                auditors.append(obj)

    return auditors
