#!/usr/bin/env python3
from __future__ import annotations

import sys

import atheris


with atheris.instrument_imports():
    from fuzz_targets import exercise_json_document


def test_one_input(data: bytes) -> None:
    exercise_json_document(data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
