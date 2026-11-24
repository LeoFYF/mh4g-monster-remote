"""Publish an unpacked directory after all files have been written."""

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator


@contextmanager
def staged_output(destination: Path) -> Iterator[Path]:
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"Output already exists: {destination}")
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".mh4g-", dir=parent) as staging:
        directory = Path(staging) / "output"
        yield directory
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"Output already exists: {destination}")
        directory.rename(destination)
