"""Locate and enumerate RomFS files in decrypted 3DS cartridges and updates."""

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator


class CciFormatError(Exception):
    """The image cannot be read or the requested RomFS member does not exist."""


_NULL_ENTRY = 0xFFFFFFFF
_DIRECTORY_ENTRY = struct.Struct("<6I")
_FILE_ENTRY = struct.Struct("<IIQQII")


@dataclass(frozen=True)
class _RomfsLayout:
    directories: tuple[int, int]
    files: tuple[int, int]
    data_start: int
    data_end: int


def _end(offset: int, size: int, limit: int, description: str) -> int:
    if offset < 0 or size < 0 or offset + size > limit:
        raise CciFormatError(f"{description} is outside its containing region")
    return offset + size


def _read(source: BinaryIO, offset: int, size: int, limit: int, description: str) -> bytes:
    _end(offset, size, limit, description)
    source.seek(offset)
    data = source.read(size)
    if len(data) != size:
        raise CciFormatError(f"Truncated {description}")
    return data


def _cartridge_program(source: BinaryIO, image_size: int) -> tuple[int, int]:
    ncsd = _read(source, 0, 0x200, image_size, "NCSD header")
    if ncsd[0x100:0x104] != b"NCSD":
        raise CciFormatError("Expected an NCSD cartridge image (.cci or .3ds)")

    card_unit = 0x200 << ncsd[0x18E]
    card_size = struct.unpack_from("<I", ncsd, 0x104)[0] * card_unit
    partition_sector, partition_sectors = struct.unpack_from("<II", ncsd, 0x120)
    if not partition_sector or not partition_sectors:
        raise CciFormatError("The NCSD application partition is missing")
    partition_start = partition_sector * card_unit
    partition_end = _end(
        partition_start, partition_sectors * card_unit, min(image_size, card_size), "NCSD application partition"
    )
    return partition_start, partition_end


def _cia_program(source: BinaryIO, image_size: int) -> tuple[int, int]:
    header = _read(source, 0, 0x2020, image_size, "CIA header")
    header_size, _, _, cert_size, ticket_size, tmd_size, _, content_size = struct.unpack_from("<IHHIIIIQ", header)
    if header_size != len(header) or not header[0x20] & 0x80:
        raise CciFormatError("Expected a CIA with program content at index 0")

    start = 0
    for size in (header_size, cert_size, ticket_size, tmd_size):
        start = (start + size + 63) & ~63
    return start, _end(start, content_size, image_size, "CIA content region")


def _romfs_region(source: BinaryIO, cia: bool) -> tuple[int, int]:
    image_size = source.seek(0, os.SEEK_END)
    program = _cia_program if cia else _cartridge_program
    partition_start, partition_end = program(source, image_size)
    ncch = _read(source, partition_start, 0x200, partition_end, "NCCH header")
    if ncch[0x100:0x104] != b"NCCH":
        raise CciFormatError("Expected a decrypted NCCH application")
    if not ncch[0x18F] & 0x04:
        raise CciFormatError("The application partition is encrypted. A decrypted game file is required.")

    content_unit = 0x200 << ncch[0x18E]
    content_size = struct.unpack_from("<I", ncch, 0x104)[0] * content_unit
    content_end = _end(partition_start, content_size, partition_end, "NCCH content")
    romfs_sector, romfs_sectors = struct.unpack_from("<II", ncch, 0x1B0)
    if not romfs_sector or not romfs_sectors or ncch[0x18F] & 0x02:
        raise CciFormatError("The application partition has no RomFS")
    romfs_start = partition_start + romfs_sector * content_unit
    romfs_end = _end(romfs_start, romfs_sectors * content_unit, content_end, "RomFS")
    return romfs_start, romfs_end


def _level3_region(source: BinaryIO, romfs_start: int, romfs_end: int) -> tuple[int, int]:
    header = _read(source, romfs_start, 0x60, romfs_end, "IVFC header")
    magic, version, master_hash_size = struct.unpack_from("<4sII", header)
    if magic != b"IVFC" or version != 0x10000:
        raise CciFormatError("Expected a retail RomFS IVFC container")

    level_size, block_shift = struct.unpack_from("<QI", header, 0x44)
    if not 5 <= block_shift < (romfs_end - romfs_start).bit_length():
        raise CciFormatError("Invalid IVFC level 3 block size")

    # Retail RomFS stores the level 3 data just after the padded master hash table.
    block_size = 1 << block_shift
    level_offset = (0x60 + master_hash_size + block_size - 1) & -block_size
    level_start = romfs_start + level_offset
    level_end = _end(level_start, level_size, romfs_end, "IVFC level 3")
    return level_start, level_end


def _iter_entries(
    source: BinaryIO,
    table: tuple[int, int],
    parent: int,
    first: int,
    layout: struct.Struct,
    visited: set[int],
) -> Iterator[tuple[int, tuple[int, ...], int]]:
    table_start, table_end = table
    offset = first
    while offset != _NULL_ENTRY:
        if offset % 4 or offset in visited:
            raise CciFormatError("Invalid RomFS sibling chain")
        visited.add(offset)

        entry_start = table_start + offset
        entry = layout.unpack(_read(source, entry_start, layout.size, table_end, "RomFS metadata entry"))
        entry_parent, next_offset = entry[:2]
        name_size = entry[-1]
        if entry_parent != parent or not name_size or name_size % 2:
            raise CciFormatError("Invalid RomFS metadata entry")

        name_start = entry_start + layout.size
        _end(name_start, name_size, table_end, "RomFS entry name")
        yield offset, entry, name_start
        offset = next_offset


def _find_entry(
    source: BinaryIO,
    table: tuple[int, int],
    parent: int,
    first: int,
    layout: struct.Struct,
    name: bytes,
) -> tuple[int, tuple[int, ...]] | None:
    for offset, entry, name_start in _iter_entries(source, table, parent, first, layout, set()):
        if entry[-1] == len(name) and _read(source, name_start, len(name), table[1], "RomFS entry name") == name:
            return offset, entry

    return None


def _layout(source: BinaryIO, cia: bool) -> _RomfsLayout:
    level_start, level_end = _level3_region(source, *_romfs_region(source, cia))
    header = _read(source, level_start, 0x28, level_end, "RomFS level 3 header")
    header_size, dir_hash, dir_hash_size, dir_meta, dir_size, file_hash, file_hash_size, file_meta, file_size, data = (
        struct.unpack("<10I", header)
    )
    if (
        header_size != len(header)
        or not header_size <= dir_hash <= dir_hash + dir_hash_size <= dir_meta
        or not dir_meta <= dir_meta + dir_size <= file_hash <= file_hash + file_hash_size <= file_meta
        or not file_meta <= file_meta + file_size <= data <= level_end - level_start
    ):
        raise CciFormatError("Invalid RomFS metadata table layout")

    return _RomfsLayout(
        directories=(level_start + dir_meta, level_start + dir_meta + dir_size),
        files=(level_start + file_meta, level_start + file_meta + file_size),
        data_start=level_start + data,
        data_end=level_end,
    )


def _root_directory(source: BinaryIO, table: tuple[int, int]) -> tuple[int, ...]:
    directory = _DIRECTORY_ENTRY.unpack(
        _read(source, table[0], _DIRECTORY_ENTRY.size, table[1], "RomFS root directory")
    )
    if directory[-1]:
        raise CciFormatError("Invalid RomFS root directory")
    return directory


def _file_range(layout: _RomfsLayout, entry: tuple[int, ...]) -> tuple[int, int]:
    offset = layout.data_start + entry[2]
    size = entry[3]
    _end(offset, size, layout.data_end, "RomFS file data")
    return offset, size


def find_romfs_file(source: BinaryIO, member: str, *, cia: bool = False) -> tuple[int, int]:
    """Return the absolute offset and length of an exact RomFS path."""
    parts = member.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") or "\x00" in part or ":" in part for part in parts):
        raise CciFormatError(f"Invalid RomFS member path: {member!r}")
    try:
        names = [part.encode("utf-16-le") for part in parts]
    except UnicodeEncodeError as error:
        raise CciFormatError(f"Invalid RomFS member path: {member!r}") from error

    layout = _layout(source, cia)
    directory_offset = 0
    directory = _root_directory(source, layout.directories)

    for name in names[:-1]:
        found = _find_entry(source, layout.directories, directory_offset, directory[2], _DIRECTORY_ENTRY, name)
        if found is None:
            raise CciFormatError(f"RomFS member not found: {member!r}")
        directory_offset, directory = found

    found = _find_entry(source, layout.files, directory_offset, directory[3], _FILE_ENTRY, names[-1])
    if found is None:
        raise CciFormatError(f"RomFS member not found: {member!r}")

    return _file_range(layout, found[1])


def _entry_name(source: BinaryIO, offset: int, size: int, limit: int, siblings: set[str]) -> str:
    try:
        name = _read(source, offset, size, limit, "RomFS entry name").decode("utf-16-le")
    except UnicodeDecodeError as error:
        raise CciFormatError("Invalid UTF-16 RomFS entry name") from error
    if name in ("", ".", "..") or any(char in name for char in "/\\\x00"):
        raise CciFormatError(f"Invalid RomFS entry name: {name!r}")
    if name in siblings:
        raise CciFormatError(f"Repeated RomFS entry name: {name!r}")
    siblings.add(name)
    return name


def iter_romfs_files(source: BinaryIO, *, cia: bool = False) -> Iterator[tuple[str, int, int]]:
    """Yield each RomFS file's slash-separated path, absolute offset and byte length."""
    layout = _layout(source, cia)
    pending = [("", 0, _root_directory(source, layout.directories))]
    visited_directories = {0}
    visited_files: set[int] = set()
    while pending:
        prefix, parent, directory = pending.pop()
        siblings: set[str] = set()
        for offset, entry, name_start in _iter_entries(
            source, layout.directories, parent, directory[2], _DIRECTORY_ENTRY, visited_directories
        ):
            name = _entry_name(source, name_start, entry[-1], layout.directories[1], siblings)
            pending.append((f"{prefix}{name}/", offset, entry))
        for _, entry, name_start in _iter_entries(
            source, layout.files, parent, directory[3], _FILE_ENTRY, visited_files
        ):
            name = _entry_name(source, name_start, entry[-1], layout.files[1], siblings)
            offset, size = _file_range(layout, entry)
            yield f"{prefix}{name}", offset, size
