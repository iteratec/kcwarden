from pathlib import Path
from typing import Type

from kcwarden.api import Monitor, Auditor
from kcwarden.utils.auditor_importing import get_auditors_from_directory, get_auditors_from_package


def test_get_auditors_from_directory():
    test_data_path = Path(__file__).parent / "test_data"
    result = get_auditors_from_directory(test_data_path)
    verify_results(result)


def test_get_auditors_from_package():
    from tests.utils import test_data  # noqa: PLC0415

    result = get_auditors_from_package(test_data)
    verify_results(result)


def verify_results(result):
    assert len(result) == 5
    assert_class_exits_in_list("Plugin1", result)
    assert_class_exits_in_list("Plugin2", result)
    assert_class_exits_in_list("Plugin3", result)
    assert_class_exits_in_list("Plugin4", result)
    assert_class_exits_in_list("Plugin5", result)
    for clz in result:
        assert issubclass(clz, Auditor)
        if clz.__name__ == "Plugin4":
            assert issubclass(clz, Monitor)


def assert_class_exits_in_list(clz_name: str, class_list: list[Type]):
    assert any(True for clz in class_list if clz.__name__ == clz_name)
