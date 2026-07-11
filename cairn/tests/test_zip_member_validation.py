from __future__ import annotations

import io
import warnings
import zipfile

import pytest

from cairn.server.source_service import _validated_zip_members


def _archive(entries: list[tuple[str, bytes]]) -> zipfile.ZipFile:
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w") as output:
            for name, content in entries:
                output.writestr(name, content)
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_case_distinct_zip_paths_are_preserved():
    with _archive(
        [
            ("Less-24/Logged-in.php", b"upper"),
            ("Less-24/logged-in.php", b"lower"),
        ]
    ) as archive:
        members = _validated_zip_members(archive)

    assert [path.as_posix() for _, path in members] == [
        "Less-24/Logged-in.php",
        "Less-24/logged-in.php",
    ]


def test_exact_duplicate_zip_path_is_rejected():
    with _archive(
        [
            ("src/index.php", b"first"),
            ("src/index.php", b"second"),
        ]
    ) as archive:
        with pytest.raises(ValueError, match="ZIP contains a duplicate path: src/index.php"):
            _validated_zip_members(archive)
