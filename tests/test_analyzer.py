"""Tests for analyzer - call site detection."""

from pathlib import Path

import tree_sitter
import tree_sitter_python

from vulntriage.analyzer import find_call_sites, check_dangerous_inputs, CallSite
from vulntriage.symbol_table import build_symbol_table

# Initialize parser
_LANGUAGE = tree_sitter.Language(tree_sitter_python.language())
_PARSER = tree_sitter.Parser()
_PARSER.language = _LANGUAGE


def parse_and_analyze(code: str, target_modules: set[str] | None = None) -> list[CallSite]:
    """Helper to parse code and find call sites."""
    tree = _PARSER.parse(code.encode("utf-8"))
    symbol_table = build_symbol_table(Path("<test>"), tree.root_node)
    return find_call_sites(Path("<test>"), tree.root_node, symbol_table, target_modules)


def test_simple_function_call() -> None:
    """Find a simple function call."""
    code = """\
import requests
response = requests.get("https://example.com")
"""
    calls = parse_and_analyze(code)
    assert len(calls) == 1
    assert calls[0].callee == "requests.get"
    assert calls[0].line == 2


def test_aliased_import_call() -> None:
    """Resolve aliased imports correctly."""
    code = """\
import requests as r
response = r.get("https://example.com")
"""
    calls = parse_and_analyze(code)
    assert len(calls) == 1
    assert calls[0].callee == "requests.get"


def test_from_import_call() -> None:
    """Resolve from imports correctly."""
    code = """\
from requests import get
response = get("https://example.com")
"""
    calls = parse_and_analyze(code)
    assert len(calls) == 1
    assert calls[0].callee == "requests.get"


def test_nested_attribute_call() -> None:
    """Handle nested attribute access."""
    code = """\
import xml.etree.ElementTree as ET
tree = ET.parse("file.xml")
"""
    calls = parse_and_analyze(code)
    assert len(calls) == 1
    assert calls[0].callee == "xml.etree.ElementTree.parse"


def test_filter_by_target_modules() -> None:
    """Only return calls to target modules."""
    code = """\
import requests
import os
requests.get("url")
os.path.join("a", "b")
"""
    calls = parse_and_analyze(code, target_modules={"requests"})
    assert len(calls) == 1
    assert calls[0].callee == "requests.get"


def test_no_target_modules_returns_all() -> None:
    """Without target_modules, return all calls."""
    code = """\
import requests
import os
requests.get("url")
os.path.join("a", "b")
print("hello")
"""
    calls = parse_and_analyze(code, target_modules=None)
    assert len(calls) >= 3  # requests.get, os.path.join, print


def test_method_chain_call() -> None:
    """Handle method chains."""
    code = """\
import requests
response = requests.get("url").json()
"""
    calls = parse_and_analyze(code, target_modules=None)
    # Should find both requests.get and .json()
    callees = [c.callee for c in calls]
    assert "requests.get" in callees


def test_unresolved_call() -> None:
    """Unresolved calls still get recorded."""
    code = """\
some_func("hello")
"""
    calls = parse_and_analyze(code, target_modules=None)
    assert len(calls) == 1
    assert calls[0].callee == "some_func"


def test_context_extraction() -> None:
    """Context should include surrounding lines."""
    code = """\
# Line 1
# Line 2
import requests
# Line 4
requests.get("url")
# Line 6
# Line 7
"""
    calls = parse_and_analyze(code, target_modules={"requests"})
    assert len(calls) == 1
    # Context should include lines around the call
    assert "requests.get" in calls[0].context


def test_check_dangerous_inputs_sys_argv() -> None:
    """Detect sys.argv in context."""
    call = CallSite(
        file_path=Path("<test>"),
        line=5,
        column=0,
        callee="os.system",
        context="cmd = sys.argv[1]\nos.system(cmd)",
    )
    assert check_dangerous_inputs(call) is True


def test_check_dangerous_inputs_os_environ() -> None:
    """Detect os.environ in context."""
    call = CallSite(
        file_path=Path("<test>"),
        line=5,
        column=0,
        callee="subprocess.run",
        context="val = os.environ.get('PATH')\nsubprocess.run(val)",
    )
    assert check_dangerous_inputs(call) is True


def test_check_dangerous_inputs_clean() -> None:
    """Clean context should return False."""
    call = CallSite(
        file_path=Path("<test>"),
        line=5,
        column=0,
        callee="requests.get",
        context="response = requests.get('https://example.com')",
    )
    assert check_dangerous_inputs(call) is False


def test_multiple_calls_same_line() -> None:
    """Handle multiple calls on the same line."""
    code = """\
import requests
x = requests.get("a") or requests.post("b")
"""
    calls = parse_and_analyze(code, target_modules={"requests"})
    assert len(calls) == 2
    callees = sorted([c.callee for c in calls])
    assert callees == ["requests.get", "requests.post"]


def test_type_checking_calls_skipped() -> None:
    """Calls inside TYPE_CHECKING blocks should be skipped."""
    code = """\
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import requests
    requests.get("url")  # Should be skipped
else:
    import os
    os.path.join("a", "b")  # Should be included
"""
    calls = parse_and_analyze(code, target_modules=None)
    callees = [c.callee for c in calls]
    assert "requests.get" not in callees
    assert "os.path.join" in callees


def test_method_chain_not_resolved_to_module() -> None:
    """Method chains like .json() on call results should not be resolved."""
    code = """\
import requests
import json
response = requests.get("url").json()
"""
    calls = parse_and_analyze(code, target_modules={"json"})
    # .json() on requests.get(...) should NOT match json module
    callees = [c.callee for c in calls]
    assert "json" not in callees


def test_method_chain_base_call_still_captured() -> None:
    """The base call in a method chain should still be captured."""
    code = """\
import requests
response = requests.get("url").json()
"""
    calls = parse_and_analyze(code, target_modules={"requests"})
    callees = [c.callee for c in calls]
    assert "requests.get" in callees
