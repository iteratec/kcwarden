import importlib
import inspect
import logging
import pkgutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Type

from kcwarden.api import Auditor

logger = logging.getLogger(__name__)


def get_auditors_from_directory(directory: Path) -> list[Type[Auditor]]:
    """
    Recursively collect all auditors from the Python modules inside a directory.
    The directory must be a Python package.
    """

    # Append the parent directory to the path thus we can import modules from there
    sys.path.append(str(directory.parent))

    if not (directory / "__init__.py").exists():
        raise ValueError(f"Directory {directory} is not a Python package - the __init__.py file is missing")

    module = importlib.import_module(directory.name)

    return get_auditors_from_package(module)


def get_auditors_from_package(package: ModuleType) -> list[Type[Auditor]]:
    """
    Recursively collect all auditors in a package and its subpackages.
    """
    auditors = []
    visited_modules = set()

    def recurse(module: ModuleType):
        if module in visited_modules:
            return
        visited_modules.add(module)

        for _, modname, is_pkg in pkgutil.iter_modules(module.__path__):
            full_name = module.__name__ + "." + modname
            try:
                sub_module = importlib.import_module(full_name)
            except ImportError as e:
                logger.error(f"Error importing module {full_name}: {e}")
                continue

            auditors.extend(collect_auditors_of_module(sub_module))

            # If it's a package, recurse into it
            if is_pkg:
                recurse(sub_module)

    recurse(package)

    return auditors


def collect_auditors_of_module(module) -> list[Type[Auditor]]:
    auditors_of_module = []
    # Inspect the module to find classes that inherit from Auditor
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if issubclass(obj, Auditor) and obj.__module__ == module.__name__ and not inspect.isabstract(obj):
            logger.debug(f"Found class {name} in {module} that inherits from {Auditor}")
            auditors_of_module.append(obj)
    return auditors_of_module
