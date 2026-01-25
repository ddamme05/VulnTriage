"""Smoke tests for Python import parsing via tree-sitter."""

from pathlib import Path

import tree_sitter
import tree_sitter_python

from vulntriage.symbol_table import build_symbol_table

_LANGUAGE = tree_sitter.Language(tree_sitter_python.language())
_PARSER = tree_sitter.Parser()
_PARSER.language = _LANGUAGE


def parse_and_build(code: str):
    """Parse Python code and build a symbol table."""
    tree = _PARSER.parse(code.encode("utf-8"))
    return build_symbol_table(Path("<test>"), tree.root_node)


def test_simple_import() -> None:
    st = parse_and_build("import requests")
    assert st.resolve_alias("requests") == "requests"


def test_import_with_alias() -> None:
    st = parse_and_build("import requests as r")
    assert st.resolve_alias("r") == "requests"


def test_from_import_single_name() -> None:
    st = parse_and_build("from requests import get")
    assert st.resolve_alias("get") == "requests.get"


def test_from_import_alias() -> None:
    st = parse_and_build("from requests import get as g")
    assert st.resolve_alias("g") == "requests.get"


def test_dotted_module_from_import() -> None:
    st = parse_and_build("from requests.sessions import Session")
    assert st.resolve_alias("Session") == "requests.sessions.Session"


def test_multiple_imports_one_statement() -> None:
    st = parse_and_build("import os, sys")
    assert st.resolve_alias("os") == "os"
    assert st.resolve_alias("sys") == "sys"


def test_multiple_from_import_names() -> None:
    st = parse_and_build("from os.path import join, dirname")
    assert st.resolve_alias("join") == "os.path.join"
    assert st.resolve_alias("dirname") == "os.path.dirname"


def test_mixed_aliases_from_import() -> None:
    st = parse_and_build("from collections import deque as dq, defaultdict")
    assert st.resolve_alias("dq") == "collections.deque"
    assert st.resolve_alias("defaultdict") == "collections.defaultdict"


def test_dotted_module_with_alias() -> None:
    st = parse_and_build("import xml.etree.ElementTree as ET")
    assert st.resolve_alias("ET") == "xml.etree.ElementTree"


def test_reimport_overrides_previous() -> None:
    code = """\
import requests as r
import httpx as r
"""
    st = parse_and_build(code)
    assert st.resolve_alias("r") == "httpx"


def test_from_import_override() -> None:
    code = """\
from requests import get as r
from httpx import get as r
"""
    st = parse_and_build(code)
    assert st.resolve_alias("r") == "httpx.get"


def test_relative_import_returns_none() -> None:
    code = """\
from . import utils
from ..core import thing
"""
    st = parse_and_build(code)
    assert st.resolve_alias("utils") is None
    assert st.resolve_alias("thing") is None


def test_star_import_no_bindings() -> None:
    st = parse_and_build("from math import *")
    assert st.resolve_alias("sqrt") is None


def test_parenthesized_import_list() -> None:
    code = """\
from os.path import (
    join,
    dirname as dn,
)
"""
    st = parse_and_build(code)
    assert st.resolve_alias("join") == "os.path.join"
    assert st.resolve_alias("dn") == "os.path.dirname"


def test_type_checking_imports_ignored() -> None:
    code = """\
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import requests as r
"""
    st = parse_and_build(code)
    assert st.resolve_alias("r") is None


def test_type_checking_else_branch_included() -> None:
    """Imports in else branch of TYPE_CHECKING should be included."""
    code = """\
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import typing_only
else:
    import runtime_only
"""
    st = parse_and_build(code)
    assert st.resolve_alias("typing_only") is None
    assert st.resolve_alias("runtime_only") == "runtime_only"


def test_type_checking_qualified_name() -> None:
    """typing.TYPE_CHECKING should be recognized."""
    code = """\
import typing
if typing.TYPE_CHECKING:
    import type_only
"""
    st = parse_and_build(code)
    assert st.resolve_alias("type_only") is None


def test_type_checking_aliased() -> None:
    """Aliased TYPE_CHECKING (e.g., t.TYPE_CHECKING) should be recognized."""
    code = """\
import typing as t
if t.TYPE_CHECKING:
    import type_only
"""
    st = parse_and_build(code)
    assert st.resolve_alias("type_only") is None
