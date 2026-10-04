#!/usr/bin/env python3
"""Read-only verification for the one named-sheet mortgage XLS copy."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

import xlrd

ORIGINAL_SHA256 = "c31a1eb6703ac0e883c311bb5f05768f29f160bfd74fb58103d372ebbcda7e63"
COPY_SHA256 = "127a1fca045d1d2b67544237a59e3cbef7ef1f80cd28cce9839ca2c94baf4767"
ORIGINAL_NAME = "Mortgage Rates 2026-10-01.xls"
COPY_NAME = "Mechanize Calc Qualification.xls"
CHECKPOINT_SHEET = "Automation Checkpoint"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def formula_map_function():
    path = Path(__file__).with_name("verify-legacy.py")
    spec = importlib.util.spec_from_file_location("mortgage_verify_legacy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.formula_map


def assert_same_sheet_values(original, copied, name):
    source = original.sheet_by_name(name)
    target = copied.sheet_by_name(name)
    assert (source.nrows, source.ncols) == (target.nrows, target.ncols), f"{name}: dimensions changed"
    for row in range(source.nrows):
        for column in range(source.ncols):
            left = source.cell(row, column)
            right = target.cell(row, column)
            assert left.ctype == right.ctype and left.value == right.value, (
                f"{name}!R{row + 1}C{column + 1}: source cell changed"
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    original_path = args.directory / ORIGINAL_NAME
    copy_path = args.directory / COPY_NAME
    original_hash = sha256(original_path)
    copy_hash = sha256(copy_path)
    assert original_hash == ORIGINAL_SHA256, "original XLS changed"
    assert copy_hash == COPY_SHA256, "named-sheet XLS copy differs from qualified artifact"

    original = xlrd.open_workbook(str(original_path), on_demand=False)
    copied = xlrd.open_workbook(str(copy_path), on_demand=False)
    try:
        assert original.biff_version == 80 and copied.biff_version == 80, "expected BIFF8 workbooks"
        original_names = original.sheet_names()
        copied_names = copied.sheet_names()
        assert copied_names == [CHECKPOINT_SHEET] + original_names, "copy must add exactly one leading checkpoint sheet"

        checkpoint = copied.sheet_by_name(CHECKPOINT_SHEET)
        nonempty = []
        for row in range(checkpoint.nrows):
            for column in range(checkpoint.ncols):
                cell = checkpoint.cell(row, column)
                if cell.ctype not in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK):
                    nonempty.append((row, column, cell.value))
        assert not nonempty, f"checkpoint sheet is not blank: {nonempty[:3]}"

        for name in original_names:
            assert_same_sheet_values(original, copied, name)

        formula_map = formula_map_function()
        original_formulas = formula_map(original_path, original, sheet_index=0)
        copied_formulas = formula_map(copy_path, copied, sheet_index=1)
        assert original_formulas, "original Sheet1 formula records missing"
        assert copied_formulas == original_formulas, "stored Sheet1 BIFF formulas changed after sheet insertion"
    finally:
        original.release_resources()
        copied.release_resources()

    print(json.dumps({
        "artifactVerified": True,
        "businessStatus": "unverified",
        "original": {"path": str(original_path), "sha256": original_hash, "unchanged": True},
        "copy": {"path": str(copy_path), "sha256": copy_hash},
        "sheetNames": copied_names,
        "addedSheet": CHECKPOINT_SHEET,
        "addedSheetBlank": True,
        "originalValuesPreservedByName": True,
        "storedFormulasPreserved": {"sheet": "Sheet1", "cells": sorted(original_formulas)},
        "checks": ["BIFF8", "pinned source and copy hashes", "one added blank sheet", "all original cells by sheet name", "stored BIFF formulas"],
        "limitations": ["Does not resolve the Insert Sheet operation receipt.", "Does not establish Mechanize business success."],
    }, indent=2))


if __name__ == "__main__":
    main()
