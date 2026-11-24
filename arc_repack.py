"""Rebuild an MH4G ARC v19 without modifying the source image."""

import os
import struct
import tempfile
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Iterator

if TYPE_CHECKING:
    from arc_viewer import ArcEntry


_CHUNK_SIZE = 64 * 1024
_HEADER_SIZE = 12
_ENTRY_SIZE = 80
_ENTRY_SIZE_OFFSET = 68
_MAX_UNPACKED_SIZE = (1 << 29) - 1
_MAX_STORED_VALUE = (1 << 32) - 1


class ArcRepackError(Exception):
    """The edited payloads or source archive cannot be repacked."""


def _read_range(source: BinaryIO, offset: int, length: int) -> Iterator[bytes]:
    source.seek(offset)
    while length:
        chunk = source.read(min(length, _CHUNK_SIZE))
        if not chunk:
            raise ArcRepackError("Source ARC ended before the requested range.")
        length -= len(chunk)
        yield chunk


def _copy_range(source: BinaryIO, offset: int, length: int, output: BinaryIO) -> None:
    for chunk in _read_range(source, offset, length):
        output.write(chunk)


def _matches_original(
    source: BinaryIO, offset: int, entry: "ArcEntry", replacement: BinaryIO
) -> bool:
    decoder = zlib.decompressobj()
    unpacked = 0
    try:
        for chunk in _read_range(source, offset, entry.stored_size):
            while chunk:
                data = decoder.decompress(chunk, _CHUNK_SIZE)
                chunk = decoder.unconsumed_tail
                unpacked += len(data)
                if unpacked > entry.unpacked_size or decoder.unused_data:
                    raise ArcRepackError(f"Invalid original payload for {entry.path!r}.")
                if replacement.read(len(data)) != data:
                    return False
    except zlib.error as error:
        raise ArcRepackError(f"Invalid original payload for {entry.path!r}: {error}") from error
    if not decoder.eof or unpacked != entry.unpacked_size:
        raise ArcRepackError(f"Incomplete or size-mismatched original payload for {entry.path!r}.")
    return not replacement.read(1)


def _compress_replacement(replacement: BinaryIO, output: BinaryIO) -> int:
    encoder = zlib.compressobj()
    unpacked = 0
    replacement.seek(0)
    while chunk := replacement.read(_CHUNK_SIZE):
        unpacked += len(chunk)
        if unpacked > _MAX_UNPACKED_SIZE:
            raise ArcRepackError("Replacement exceeds the ARC v19 unpacked size limit.")
        output.write(encoder.compress(chunk))
    output.write(encoder.flush())
    return unpacked


def _rebuild_entries(
    source: BinaryIO,
    start: int,
    length: int,
    entries: Sequence["ArcEntry"],
    replacements: Mapping[int, Path],
    output: BinaryIO,
) -> int:
    table_end = _HEADER_SIZE + len(entries) * _ENTRY_SIZE
    original_position = table_end
    _copy_range(source, start, table_end, output)
    changed_count = 0

    for index, entry in sorted(enumerate(entries), key=lambda indexed: indexed[1].offset):
        original_end = entry.offset + entry.stored_size
        if entry.offset < original_position or original_end > length:
            raise ArcRepackError(f"Entry {index + 1} overlaps another range or falls outside the ARC.")

        _copy_range(source, start + original_position, entry.offset - original_position, output)
        new_offset = output.tell()
        unpacked = entry.unpacked_size
        changed = False
        if index in replacements:
            if entry.flags not in (1, 5):
                raise ArcRepackError(f"Unsupported ARC compression flag {entry.flags} in {entry.path!r}.")
            with replacements[index].open("rb") as replacement:
                changed = not _matches_original(source, start + entry.offset, entry, replacement)
                if changed:
                    unpacked = _compress_replacement(replacement, output)
                    changed_count += 1

        if not changed:
            _copy_range(source, start + entry.offset, entry.stored_size, output)
        new_end = output.tell()
        stored = new_end - new_offset
        if max(new_offset, stored) > _MAX_STORED_VALUE:
            raise ArcRepackError("The rebuilt data exceeds the ARC v19 size or offset limit.")
        if changed or new_offset != entry.offset:
            output.seek(_HEADER_SIZE + index * _ENTRY_SIZE + _ENTRY_SIZE_OFFSET)
            output.write(struct.pack("<III", stored, (entry.flags << 29) | unpacked, new_offset))
            output.seek(new_end)
        original_position = original_end

    _copy_range(source, start + original_position, length - original_position, output)
    return changed_count


def repack_arc(
    source: BinaryIO,
    start: int,
    length: int,
    entries: Sequence["ArcEntry"],
    replacements: Mapping[int, Path],
    destination: Path,
) -> int:
    """Write a new ARC and return the number of payloads whose content changed."""
    if start < 0 or length < _HEADER_SIZE + len(entries) * _ENTRY_SIZE:
        raise ArcRepackError("Source ARC range is smaller than its entry table.")
    if any(not 0 <= index < len(entries) for index in replacements):
        raise ArcRepackError("Replacement index falls outside the ARC entry table.")
    if destination.exists() or destination.is_symlink():
        raise ArcRepackError(f"Output already exists: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".arc-repack-", dir=destination.parent) as directory:
        staged = Path(directory) / "archive.arc"
        with staged.open("wb") as output:
            if replacements:
                changed_count = _rebuild_entries(source, start, length, entries, replacements, output)
            else:
                _copy_range(source, start, length, output)
                changed_count = 0
        try:
            if os.name == "nt":
                staged.rename(destination)
            else:
                os.link(staged, destination)
        except FileExistsError as error:
            raise ArcRepackError(f"Output already exists: {destination}") from error
    return changed_count
