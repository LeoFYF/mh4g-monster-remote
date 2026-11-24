"""Build the experimental em114 fixed-round LayeredFS replacement."""

from pathlib import Path
from struct import pack_into, unpack_from
from subprocess import run
from sys import executable

ROOT = Path(__file__).resolve().parent
DUMP = ROOT / "mh4g-unpacked"
BUILD = ROOT / "build" / "em114-fixed-round-paced-no-area-change"
REMOTE_BUILD = ROOT / "build" / "em114-remote-chains"
MEMBER = Path("enemy/em048/data/em048_cmd.type-3AABBA02")
TICKS_PER_SECOND = 60
AREA_CHANGE = b"\x03\x04"
SCRIPT_RESTART = b"\x20\x00\xff"
# Explicit cases in the uEm048 reaction dispatcher at 0x83E2A8.
ZINOGRE_REACTIONS = (
    0x07, 0x08, 0x14, 0x1B, 0x1D, 0x1E, 0x1F, 0x20, 0x25, 0x2A, 0x2B,
    0x44, 0x45, 0x52, 0x53, 0x59, 0x60, 0x61, *range(0x62, 0x67), 0x6E,
    0x70, 0x72, 0x87, 0x94, 0x96, 0x9B, 0x9D, 0xA1, 0xA7, 0xA9, 0xAB,
    0xAF, 0xB4, 0xB5, 0xBB, 0xBC, 0xBD, 0xBE, 0xC5, 0xD2, 0xD9, 0xE1,
)
# Two empty monster-ID conditions. Both pass control to the original script.
REMOTE_HEADER = bytes.fromhex("46 00 46 01 F4 46 FF 46 00 46 01 F3 46 FF")


def instructions(data, offset, length, widths):
    end = offset + length
    while offset < end:
        opcode = data[offset]
        if opcode == 0xFF:
            size = 1
        else:
            width = widths[opcode]
            if width & 0x80:
                mode = data[offset + 1]
                if mode == 0:
                    width = (width + 1) & 0xF
                elif mode == 1:
                    width = {0x90: 3, 0xA0: 4, 0xB0: 5}.get(width & 0xF0, 2)
                else:
                    width = 1
            size = 1 + width
        if offset + size > end:
            raise ValueError(f"Instruction at {offset:#x} overruns its EMC script")
        yield data[offset:offset + size]
        offset += size


def script_actions(data, widths, monster_id=114):
    actions = {}
    group_count, = unpack_from("<I", data, 8)
    for group in range(group_count):
        count, table = unpack_from("<II", data, 0x10 + group * 16)
        for script in range(count):
            length, offset = unpack_from("<II", data, table + script * 16)
            monster_cases = []
            for token in instructions(data, offset, length, widths):
                if token[0] == 0x46:
                    mode = token[1]
                    if mode == 0:
                        monster_cases.append([True, False])
                    elif mode == 1:
                        matches = token[2] == monster_id
                        monster_cases[-1][0] = matches
                        monster_cases[-1][1] |= matches
                    elif mode == 2:
                        monster_cases[-1][0] = not monster_cases[-1][1]
                    elif mode == 0xFF:
                        monster_cases.pop()
                if token[0] == 0 and all(current for current, _ in monster_cases):
                    actions.setdefault(token[1:], None)
            if monster_cases:
                raise ValueError(f"Unclosed monster condition in G{group}/S{script}")
    actions.pop(AREA_CHANGE, None)
    return sorted(actions)


def combat_actions(data, widths):
    return [action for action in script_actions(data, widths) if action[0] in (2, 3, 7)]


def remote_actions():
    original, widths, _ = load_actions()
    native = (b"\x00\x00", b"\x02\x43", b"\x07\xb0", b"\x07\xb1",
              b"\x07\xd7", b"\x07\xd8", b"\x07\xdc")
    return sorted(set(script_actions(original, widths)).union(native))


def monster_action_catalog():
    _, widths, _ = load_actions()
    catalog = {}
    for directory in sorted((DUMP / "arc/data").glob("em[0-9][0-9][0-9].arc")):
        monster_id = int(directory.name[2:5])
        actions = {
            action
            for source in directory.rglob("*_cmd.type-3AABBA02")
            for action in script_actions(source.read_bytes(), widths, monster_id)
            if action[0] <= 0xD
        }
        catalog[monster_id] = sorted(actions)
    catalog[114] = remote_actions()
    for monster_id in (48, 49, 114):
        catalog[monster_id] = sorted(set(catalog[monster_id]).union(
            bytes((0xA, number)) for number in ZINOGRE_REACTIONS
        ))
    catalog[114] = sorted(set(catalog[114]).union((b"\x01\x29",)))
    for monster_id in (48, 114):
        catalog[monster_id] = sorted(set(catalog[monster_id]).union((b"\x01\x04", b"\x01\x05")))
    return catalog


def localized_monster_names():
    source = DUMP / "update-1.2/arc/data/core_common.arc/msg/emName_jpn.type-62440501"
    data = source.read_bytes()
    if data[:4] != b"lmd\0":
        raise ValueError("Unexpected monster name table format")
    count, = unpack_from("<I", data, 0x10)
    table, end = unpack_from("<II", data, 0x1C)
    names = {}
    for monster_id in range(count):
        offset, units, _ = unpack_from("<III", data, table + monster_id * 12)
        if not table + count * 12 <= offset <= offset + units * 2 <= end:
            raise ValueError(f"Invalid name range for em{monster_id:03}")
        name = data[offset:offset + units * 2].decode("utf-16-le").rstrip("\0")
        if name:
            names[monster_id] = name
    return names


def wait(seconds):
    """Emit one or more EMC timer loads, each with a one-byte duration."""
    ticks = seconds * TICKS_PER_SECOND
    return b"".join(
        bytes((0x2F, min(200, ticks - start)))
        for start in range(0, ticks, 200)
    )


def load_actions():
    source = DUMP / "arc" / "data" / "em114.arc" / MEMBER
    original = source.read_bytes()
    code = (DUMP / "update-1.2" / "exefs" / "code.bin").read_bytes()
    widths = code[0xEDF240:0xEDF240 + 146]
    if original[:4] != b"EMC\x00" or len(original) != 14560:
        raise ValueError("Unexpected em114 EMC. This builder targets the documented 1.2 dump.")
    actions = combat_actions(original, widths)
    if not actions:
        raise ValueError("No combat actions found")
    return original, widths, actions


def replace_entry(original, script):
    result = bytearray(original)
    group_zero, = unpack_from("<I", original, 0x14)
    start = (len(result) + 15) & ~15
    pack_into("<II", result, group_zero, len(script), start)
    result.extend(bytes(start - len(result)))
    result.extend(script)
    return result, start


def main():
    original, widths, actions = load_actions()
    # Action op 00 yields after each request. Op 2F waits when the script resumes.
    # Op 20 00 calls G0/S0 again after the final wait.
    # FF supplies a valid script terminator for the saved return position.
    script = wait(1).join(b"\x00" + action for action in actions)
    script += wait(10) + SCRIPT_RESTART
    result, start = replace_entry(original, script)
    tokens = list(instructions(result, start, len(script), widths))
    requested = []
    intervals = []
    for token in tokens[:-2]:
        if token[0] == 0:
            requested.append(bytes(token[1:]))
            intervals.append(0)
        elif token[0] == 0x2F and intervals:
            intervals[-1] += token[1]
        else:
            raise ValueError("Unexpected instruction in the paced round")
    expected_intervals = [TICKS_PER_SECOND] * (len(actions) - 1)
    expected_intervals.append(10 * TICKS_PER_SECOND)
    if requested != actions or intervals != expected_intervals:
        raise ValueError("Round failed its action order or timing check")
    if tokens[-2:] != [b"\x20\x00", b"\xff"]:
        raise ValueError("Round failed its restart instruction check")

    write_build(BUILD, result, actions)


def build_remote():
    original, widths, actions = load_actions()
    group_zero, = unpack_from("<I", original, 0x14)
    length, offset = unpack_from("<II", original, group_zero)
    vanilla = original[offset:offset + length]
    script = REMOTE_HEADER + vanilla
    if list(instructions(vanilla, 0, len(vanilla), widths))[-1] != b"\xff":
        raise ValueError("Original selector is missing its terminator")
    result, _ = replace_entry(original, script)
    write_build(REMOTE_BUILD, result, actions)


def write_build(directory, result, actions):
    edits = directory / "edits"
    replacement = edits / MEMBER
    destination = directory / "000400000011D700" / "romfs" / "data" / "em114.arc"
    if destination.exists():
        raise FileExistsError(destination)
    replacement.parent.mkdir(parents=True, exist_ok=True)
    replacement.write_bytes(result)
    run(
        [executable, "-B", str(ROOT / "arc_viewer.py"),
         str(DUMP / "romfs" / "data" / "em114.arc"), "--replace-from", str(edits),
         "--output", str(destination)],
        check=True,
    )
    (directory / "round-order.txt").write_text(
        "\n".join(f"{action[0]:X}/{action[1]:02X}" for action in actions) + "\n",
        encoding="utf-8",
    )
    print(f"{len(actions)} distinct direct combat requests")


if __name__ == "__main__":
    main()
