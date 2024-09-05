from pathlib import Path
from typing import Type

from kcwarden.api import Monitor, Auditor
from kcwarden.utils.plugins import get_auditors


def test_get_auditors():
    test_data_path = Path(__file__).parent / "test_data"
    result = get_auditors(test_data_path)
    assert len(result) == 4
    assert_class_exits_in_list("Plugin1", result)
    assert_class_exits_in_list("Plugin2", result)
    assert_class_exits_in_list("Plugin3", result)
    assert_class_exits_in_list("Plugin4", result)
    for clz in result:
        assert issubclass(clz, Auditor)
        if clz.__name__ == "Plugin4":
            assert issubclass(clz, Monitor)


def assert_class_exits_in_list(clz_name: str, class_list: list[Type]):
    assert any(True for clz in class_list if clz.__name__ == clz_name)
