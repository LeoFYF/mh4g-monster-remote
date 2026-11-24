"""List, extract, or rebuild a Monster Hunter 4G ARC archive."""

import argparse
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from os import SEEK_END
from pathlib import Path
from typing import BinaryIO

from cci_romfs import CciFormatError, find_romfs_file
from arc_repack import ArcRepackError, repack_arc
from unpack_output import staged_output

ARC_VERSION = 19
ARC_HEADER = struct.Struct("<4sHH4x")
ARC_ENTRY = struct.Struct("<64sIIII")
NON_PRINTABLE_PATH_BYTE = re.compile(rb"[^\x20-\x7e]")
WINDOWS_UNSAFE_NAME = re.compile(r'[^ -~]|[<>:"|?*]')
WINDOWS_DEVICE_NAME = re.compile(r"CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[1-9]", re.I)
TYPE_EXTENSIONS = {
    0x241F5DEB: "tex",
    0x2749C8A8: "mrl",
    0x3A6A5A4D: "strq",
    0x4A4B677C: "rev_ctr",
    0x58A15856: "mod",
}
CHUNK_SIZE = 64 * 1024


class ArcFormatError(Exception):
    """The archive is unsupported or structurally invalid."""


@dataclass(frozen=True)
class ArcEntry:
    raw_path: bytes
    offset: int
    stored_size: int
    type_hash: int
    unpacked_size: int
    flags: int

    @property
    def path(self) -> str:
        escaped = NON_PRINTABLE_PATH_BYTE.sub(lambda match: b"\\x" + match[0].hex().encode(), self.raw_path)
        return escaped.decode("ascii")


def read_arc(source: BinaryIO, start: int, length: int) -> list[ArcEntry]:
    """Read the entry table from an ARC occupying a bounded file range."""
    if length < ARC_HEADER.size:
        raise ArcFormatError("Truncated ARC header.")

    source.seek(start)
    header = source.read(ARC_HEADER.size)
    if len(header) != ARC_HEADER.size:
        raise ArcFormatError("Truncated ARC header.")

    magic, version, count = ARC_HEADER.unpack(header)
    if magic != b"ARC\0":
        raise ArcFormatError("Unsupported archive signature (expected little-endian ARC).")
    if version != ARC_VERSION:
        raise ArcFormatError(f"Unsupported ARC version {version} (expected {ARC_VERSION}).")

    table_size = count * ARC_ENTRY.size
    table_end = ARC_HEADER.size + table_size
    if table_end > length:
        raise ArcFormatError("Truncated ARC entry table.")
    table = source.read(table_size)
    if len(table) != table_size:
        raise ArcFormatError("Truncated ARC entry table.")

    entries = []
    for index, (name, type_hash, stored_size, packed_size, offset) in enumerate(ARC_ENTRY.iter_unpack(table), start=1):
        if offset < table_end or offset + stored_size > length:
            raise ArcFormatError(f"Entry {index} data range falls outside the ARC data area.")
        entries.append(ArcEntry(name.partition(b"\0")[0], offset, stored_size, type_hash,
                                packed_size & 0x1FFFFFFF, packed_size >> 29))
    return entries


def entry_paths(entries: list[ArcEntry]) -> list[Path]:
    """Map internal paths and resource types to distinct portable filenames."""
    paths = []
    files = set()
    directories = set()
    for entry in entries:
        parts = entry.raw_path.decode("ascii", "replace").replace("\\", "/").split("/")
        if any(not part or part.endswith((" ", ".")) or WINDOWS_UNSAFE_NAME.search(part)
               or WINDOWS_DEVICE_NAME.fullmatch(part.partition(".")[0].rstrip(" ")) for part in parts):
            raise ArcFormatError(f"Unsafe ARC path: {entry.path!r}")

        extension = TYPE_EXTENSIONS.get(entry.type_hash, f"type-{entry.type_hash:08X}")
        parts[-1] = f"{parts[-1]}.{extension}"
        key = tuple(part.casefold() for part in parts)
        parents = {key[:length] for length in range(1, len(key))}
        if key in files or key in directories or parents & files:
            raise ArcFormatError(f"Conflicting ARC output path: {str(Path(*parts))!r}")
        files.add(key)
        directories.update(parents)
        paths.append(Path(*parts))
    return paths


def unpack_entry(source: BinaryIO, start: int, entry: ArcEntry, target: BinaryIO) -> None:
    if entry.flags not in (1, 5):
        raise ArcFormatError(f"Unsupported ARC compression flag {entry.flags} in {entry.path!r}.")

    source.seek(start + entry.offset)
    remaining = entry.stored_size
    written = 0
    decoder = zlib.decompressobj()
    try:
        while remaining:
            packed = source.read(min(remaining, CHUNK_SIZE))
            if not packed:
                raise ArcFormatError(f"Truncated ARC payload for {entry.path!r}.")
            remaining -= len(packed)
            while packed:
                available = entry.unpacked_size - written
                decoded = decoder.decompress(packed, min(CHUNK_SIZE, available + 1))
                if len(decoded) > available:
                    raise ArcFormatError(f"Unpacked size mismatch for {entry.path!r}.")
                target.write(decoded)
                written += len(decoded)
                if decoder.eof:
                    if decoder.unused_data or remaining:
                        raise ArcFormatError(f"Trailing data after zlib stream for {entry.path!r}.")
                    break
                packed = decoder.unconsumed_tail
    except zlib.error as error:
        raise ArcFormatError(f"Invalid zlib stream for {entry.path!r}: {error}") from error

    if not decoder.eof:
        raise ArcFormatError(f"Incomplete zlib stream for {entry.path!r}.")
    if written != entry.unpacked_size:
        raise ArcFormatError(f"Unpacked size mismatch for {entry.path!r}.")


def extract_entries(source: BinaryIO, start: int, entries: list[ArcEntry], directory: Path) -> None:
    """Extract entries to a new directory inside a staged output tree."""
    paths = entry_paths(entries)
    directory.mkdir(parents=True)
    for entry, relative_path in zip(entries, paths):
        destination = directory / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as target:
            unpack_entry(source, start, entry, target)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="ARC file, decrypted 3DS cartridge, or decrypted CIA update")
    parser.add_argument("--member", help="path of the ARC inside the game's or update's RomFS")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--extract-to", type=Path, help="new directory for the decompressed ARC entries")
    actions.add_argument("--replace-from", type=Path, help="directory containing replacement ARC entries")
    parser.add_argument("--output", type=Path, help="new ARC file to write when replacing entries")
    args = parser.parse_args(argv)

    if args.member is None and args.source.suffix.lower() in {".cci", ".3ds", ".cia"}:
        parser.error("a cartridge or update requires --member, e.g. --member data/v01.arc")
    if (args.replace_from is None) != (args.output is None):
        parser.error("--replace-from and --output must be used together")

    try:
        with args.source.open("rb") as source:
            if args.member is None:
                start, length = 0, source.seek(0, SEEK_END)
            else:
                start, length = find_romfs_file(source, args.member, cia=args.source.suffix.lower() == ".cia")
            entries = read_arc(source, start, length)
            if args.extract_to is not None:
                with staged_output(args.extract_to) as directory:
                    extract_entries(source, start, entries, directory)
                print(f"Extracted {len(entries)} entries to {args.extract_to}")
                return 0
            if args.replace_from is not None:
                if not args.replace_from.is_dir():
                    raise ArcFormatError(f"Replacement directory not found: {args.replace_from}")
                replacements = {
                    index: candidate
                    for index, relative in enumerate(entry_paths(entries))
                    if (candidate := args.replace_from / relative).is_file()
                }
                count = repack_arc(source, start, length, entries, replacements, args.output)
                print(f"Wrote {args.output} ({count} entries changed)")
                return 0
    except (OSError, ArcFormatError, ArcRepackError, CciFormatError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"ARC version: {ARC_VERSION}")
    print(f"Entries: {len(entries)}")
    print(f"{'OFFSET':>10}  {'STORED SIZE':>11}  PATH")
    for entry in entries:
        print(f"{entry.offset:>10}  {entry.stored_size:>11}  {entry.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
