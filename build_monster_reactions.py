"""Build the 1.2 action catalog, including explicit native A-class reactions."""

import json
from collections import Counter
from re import finditer, escape
from struct import pack, unpack_from

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_MODE_ARM, Uc, UcError
from unicorn.arm_const import (
    UC_ARM_REG_CPSR, UC_ARM_REG_FPEXC, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_SP,
)

from build_em114_lock import IMAGE, LEGACY_CAVE
from build_em114_round import DUMP, ROOT, ZINOGRE_REACTIONS, localized_monster_names, monster_action_catalog


def native_reactions(code):
    # The same common method follows the per-species action-update method.
    tables = {}
    for match in finditer(escape(pack("<I", 0x928A7C)), code):
        table = match.start() - 0xB4
        if table % 4 or table < LEGACY_CAVE - IMAGE:
            continue
        slots = unpack_from("<8I", code, table + 0x9C)
        if all(IMAGE <= address < LEGACY_CAVE for address in slots):
            tables.setdefault(slots[5], table + IMAGE)

    cpu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    cpu.mem_map(IMAGE, (len(code) + 4095) & ~4095)
    cpu.mem_write(IMAGE, code)
    obj, work, stack, stop = 0x2100000, 0x2110000, 0x2120000, 0x2130000
    cpu.mem_map(obj, 0x40000)
    cpu.mem_write(obj + 0xE28, pack("<I", work))
    cpu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    route = call = None
    saw_action = False

    def read_action(_, _access, address, _size, _value, _data):
        nonlocal saw_action
        if address == work + 0x1CB:
            saw_action = True

    def trace(uc, address, _size, _data):
        nonlocal route, call
        if call is not None:
            if address != call + 4:
                route = call
                uc.emu_stop()
                return
            call = None
        if not saw_action or not IMAGE <= address < LEGACY_CAVE:
            return
        word, = unpack_from("<I", code, address - IMAGE)
        if word & 0x0F000000 == 0x0B000000 or word & 0x0FFFFFF0 == 0x012FFF30:
            call = address
        elif word & 0x0FFFFFF0 == 0x012FFF10 or word & 0x0FFFF000 == 0x08BD8000:
            route = address
            uc.emu_stop()

    cpu.hook_add(UC_HOOK_MEM_READ, read_action)
    cpu.hook_add(UC_HOOK_CODE, trace)
    reactions = {}
    for entry, table in tables.items():
        routes = []
        cpu.mem_write(obj, pack("<I", table))
        for number in range(256):
            route = call = None
            saw_action = False
            cpu.mem_write(work + 0x1CA, bytes((10, number)))
            cpu.reg_write(UC_ARM_REG_CPSR, 0x10)
            cpu.reg_write(UC_ARM_REG_R0, obj)
            cpu.reg_write(UC_ARM_REG_SP, stack + 0xFF0)
            cpu.reg_write(UC_ARM_REG_LR, stop)
            try:
                cpu.emu_start(entry, stop, count=100)
            except UcError:
                route = None
            routes.append(route)
        default, count = Counter(routes).most_common(1)[0]
        if default is not None and count > 128:
            actions = [number for number, branch in enumerate(routes)
                       if branch is not None and branch != default]
            if actions:
                reactions[entry] = actions
    if set(reactions[0x83F238]) != set(ZINOGRE_REACTIONS):
        raise ValueError("Extracted reactions did not match the known Zinogre dispatcher")
    return reactions


if __name__ == "__main__":
    game_code = (DUMP / "update-1.2/exefs/code.bin").read_bytes()
    reactions = native_reactions(game_code)
    manifest = {
        "actions": {key: [action.hex() for action in actions]
                    for key, actions in monster_action_catalog().items()},
        "names": localized_monster_names(),
        "reactions": reactions,
    }
    destination = ROOT / "monster-actions.json"
    destination.write_text(json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
                           encoding="utf-8")
    print(f"{len(reactions)} dispatchers, {sum(map(len, reactions.values()))} reaction routes")
