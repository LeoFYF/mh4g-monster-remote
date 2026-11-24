"""Build an IPS patch for the em114 remote-control mailbox in MH4G 1.2."""

from struct import pack, unpack_from

from build_em114_round import DUMP, ROOT


IMAGE = 0x100000
# Leave the initial padding available to existing 4G cheats.
LEGACY_CAVE = 0xDCDCD4
CAVE = 0xDCDD00
CAVE_SIGNATURE = bytes.fromhex("281e90e518309fe5082093e5000052e1")
LEGACY_CAVE_SIGNATURE = bytes.fromhex("281e90e520309fe5082093e5000052e1")
PAGE_END = 0xDCE000
# Shared frame update reached by both Teostra and Zinogre.
LEGACY_TICK = 0x83F238
TICK = 0x93641C
QUEUE = 0x93864C
SET = 0x8F87D4
SUBMIT = 0x93755C
ORIGINALS = {TICK: 0xE92D41F0, QUEUE: 0xE92D43F8, SET: 0xE92D4FFF}
HOOK_SIZE = 4
CONTROL_ADDRESS = 0x010FDF00
CONTROL_SIZE = 20
LEGACY_CONTROL_TAG = b"RMC4"
EXPANDED_CONTROL_TAG = b"RMC5"
CONTROL_TAG = b"RMC7"
STATE_CONTROL_TAG = b"RMC8"
CANCEL_CONTROL_TAG = b"RMC9"
RECOVERY_CONTROL_TAG = b"RMCA"
TARGET_CONTROL_TAG = b"RMCB"
SOLO_TARGET_CONTROL_TAG = b"RMCC"
TARGET_MODE_OFFSET = 17
TARGET_SELECT_CALL = 0x936960
TARGET_SELECT = 0x8FBD2C
TARGET_CAVE = 0xDCDCE8
AIM_SELECT_CALL = 0x8F8980
AIM_SELECT = 0x9241AC
AIM_PADDING = 0xADE55C
AIM_PADDING_END = 0xADE668
RESTART_PENALTY_TICKS = 60
FIGHT_STATE_COMMAND = 0xF0
SET_FIGHT_STATE = 0x91D190
CONTROL_TAG_ADDRESS = PAGE_END - len(CONTROL_TAG)
END_STABLE_TICKS = 12


def arm_branch(origin, target):
    displacement = target - origin - 8
    if displacement % 4 or not -0x2000000 <= displacement < 0x2000000:
        raise ValueError(f"Invalid ARM branch at {origin:#x}")
    return pack("<I", 0xEA000000 | ((displacement >> 2) & 0xFFFFFF))


def build_records():
    from keystone import Ks, KS_ARCH_ARM, KS_MODE_ARM

    arm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    cave = bytearray()

    def emit(assembly):
        address = CAVE + len(cave)
        encoded, _ = arm.asm(assembly, addr=address, as_bytes=True)
        cave.extend(encoded)
        return address

    # Primary mailbox bytes: lock, request sequence, category, action, ack,
    # mode, timeout, followed by the object/work pointers and an end counter.
    # Modes 0/1 are free/held. 2 is a manual chain, 3 an authorized submit,
    # and 4 a call into the game's manual action update.
    mailbox = emit(f"""
        ldr r1, [r0, #0xe28]
        ldr r3, ={CONTROL_ADDRESS:#x}
        ldr r2, [r3, #8]
        cmp r2, r0
        ldreq r2, [r3, #12]
        cmpeq r2, r1
        moveq r0, r3
        movne r0, #0
        bx lr
    """)
    tick = emit(f"""
        push {{r0-r8, lr}}
        mov r4, r0
        bl #{mailbox:#x}
        cmp r0, #0
        beq tick_normal
        mov r5, r0
        ldr r6, [r4, #0xe28]
        ldrb r7, [r5, #5]
        cmp r7, #2
        bne next_request

        ldrh r1, [r5, #6]
        subs r1, r1, #1
        bmi next_request
        strh r1, [r5, #6]
        ldrb r1, [r6, #0x1cf]
        cmp r1, #0
        bne native_next
        ldrb r1, [r6, #0x1dc]
        cmp r1, #0
        ldrbeq r1, [r5, #16]
        cmpeq r1, #{END_STABLE_TICKS}
        bhs next_request
        ldrb r1, [r6, #0x1ca]
        cmp r1, #0
        beq next_request
        b tick_manual

    native_next:
        ldrb r1, [r6, #0x1d0]
        ldrb r2, [r6, #0x1d1]
        ldrb r0, [r6, #0x1ca]
        cmp r0, r1
        ldrbeq r0, [r6, #0x1cb]
        cmpeq r0, r2
        bne submit_action
        ldrh r0, [r5, #6]
        subs r0, r0, #{RESTART_PENALTY_TICKS}
        bmi next_request
        strh r0, [r5, #6]
        b submit_action

    next_request:
        ldrb r7, [r5, #1]
        ldrb r1, [r5, #4]
        cmp r7, r1
        beq settle
        strb r7, [r5, #4]
        ldrb r1, [r5, #2]
        ldrb r2, [r5, #3]
        cmp r1, #{FIGHT_STATE_COMMAND}
        bne ordinary_request
        cmp r2, #2
        bhi tick_normal
        mov r0, r4
        mov r1, r2
        bl #{SET_FIGHT_STATE:#x}
        b tick_normal
    ordinary_request:
        cmp r1, #0xd
        bhi settle
        mov r0, #600
        strh r0, [r5, #6]
    submit_action:
        cmp r1, #3
        cmpeq r2, #4
        beq settle
        mov r0, #0
        strb r0, [r6, #0x1cf]
        strb r0, [r6, #0x1dc]
        strb r0, [r5, #16]
        mov r0, #3
        strb r0, [r5, #5]
        mov r0, r4
        mov r3, #0
        bl #{SUBMIT:#x}

    tick_manual:
        mov r0, #4
        strb r0, [r5, #5]
        ldrb r8, [r6, #0x144]
        ldr r3, [sp, #12]
        mov r0, r4
        bl vanilla_tick
        mov r0, #2
        strb r0, [r5, #5]
        ldrb r1, [r6, #0x144]
        cmp r1, r8
        ldrbeq r1, [r6, #0x1cf]
        cmpeq r1, #0
        bne reset_end
        add r1, r4, #0x200
        ldrh r1, [r1, #0x46]
        tst r1, #4
        ldrbne r1, [r5, #16]
        addne r1, r1, #1
        bne end_update
    reset_end:
        mov r1, #0
    end_update:
        strb r1, [r5, #16]
        pop {{r0-r8, pc}}

    settle:
        ldrb r8, [r5, #5]
        ldrb r0, [r5]
        cmp r0, #0
        bne go_idle
        cmp r8, #2
        beq go_idle
        cmp r8, #1
        bne tick_normal
        b settled
    go_idle:
        mov r0, #0
        strb r0, [r6, #0x1cf]
        ldrb r1, [r6, #0x1ca]
        ldrb r2, [r6, #0x1cb]
        orrs r0, r1, r2
        beq settled
        mov r0, #3
        strb r0, [r5, #5]
        mov r0, r4
        mov r1, #0
        mov r2, #0
        mov r3, #2
        bl #{SUBMIT:#x}
    settled:
        ldrb r0, [r5]
        strb r0, [r5, #5]
        cmp r0, #0
        streq r0, [r6, #0xb10]

    tick_normal:
        pop {{r0-r8, lr}}
    vanilla_tick:
        .word {ORIGINALS[TICK]:#x}
        b #{TICK + HOOK_SIZE:#x}
    """)
    queue = emit(f"""
        push {{r0-r3, lr}}
        bl #{mailbox:#x}
        cmp r0, #0
        beq queue_normal
        ldrb r1, [r0, #5]
        cmp r1, #4
        beq queue_normal
        cmp r1, #2
        ldrbne r1, [r0]
        cmpne r1, #1
        popeq {{r0-r3, pc}}
    queue_normal:
        pop {{r0-r3, lr}}
        .word {ORIGINALS[QUEUE]:#x}
        b #{QUEUE + HOOK_SIZE:#x}
    """)
    setter = emit(f"""
        push {{r0-r3, lr}}
        bl #{mailbox:#x}
        cmp r0, #0
        beq set_normal
        ldrb r1, [r0, #5]
        cmp r1, #3
        beq set_normal
        cmp r1, #4
        beq from_tick
        cmp r1, #2
        beq from_queue
        ldrb r1, [r0]
        cmp r1, #0
        beq set_normal
        b set_block
    from_queue:
        ldr r1, [sp, #16]
        ldr r2, =0x8fb4d4
        cmp r1, r2
        bne set_block
        b continuation
    from_tick:
        ldr r1, [sp, #16]
        ldr r2, =0x937594
        cmp r1, r2
        beq set_block
    continuation:
        ldr r1, [sp, #4]
        ldr r2, [sp, #8]
        cmp r1, #3
        cmpeq r2, #4
        beq set_block
        mov r1, #0
        strb r1, [r0, #16]
        ldr r2, [r0, #12]
        strb r1, [r2, #0x1dc]
        strb r1, [r2, #0x1cf]
    set_normal:
        pop {{r0-r3, lr}}
        .word {ORIGINALS[SET]:#x}
        b #{SET + HOOK_SIZE:#x}
    set_block:
        pop {{r0-r3, lr}}
        mov r0, #0
        bx lr
    """)
    target_tail = emit(f"""
        subne r0, r0, #2
        strbne r0, [r1, #0x1da]
        pop {{r0, lr}}
        bxne lr
        b #{TARGET_SELECT:#x}
    """)
    target_code, _ = arm.asm(f"""
        push {{r0, lr}}
        bl #{mailbox:#x}
        cmp r0, #0
        ldrbne r0, [r0, #{TARGET_MODE_OFFSET}]
        cmpne r0, #0
        b #{target_tail:#x}
    """, addr=TARGET_CAVE, as_bytes=True)
    if TARGET_CAVE + len(target_code) > CAVE:
        raise ValueError("Target selector overlaps the main code cave")
    aim_entry = AIM_PADDING + 4
    aim_code, _ = arm.asm(f"""
        push {{r0-r4, lr}}
        bl #{mailbox:#x}
        cmp r0, #0
        beq aim_original
        ldrb r0, [r0, #{TARGET_MODE_OFFSET}]
        cmp r0, #1
        beq aim_forward
    aim_original:
        pop {{r0-r4, lr}}
        b #{AIM_SELECT:#x}

    aim_forward:
        mov r4, r1
        vpush {{d8-d9}}
        add r0, r4, #0x100
        ldrh r0, [r0, #0xac]
        bl #0x5552c8
        vmov.f32 s16, s0
        add r0, r4, #0x100
        ldrh r0, [r0, #0xac]
        bl #0x555290
        vldr s1, [r4, #0x198]
        vldr s2, [r4, #0x1a0]
        mov r0, #0x41000000
        vmov s3, r0
        vmla.f32 s1, s16, s3
        vmla.f32 s2, s0, s3
        ldr r2, [sp, #24]
        vstr s1, [r2]
        ldr r1, [r4, #0x19c]
        str r1, [r2, #4]
        vstr s2, [r2, #8]
        ldr r3, [sp, #28]
        mov r0, #0
        str r0, [r2, #12]
        strb r0, [r3]
        vpop {{d8-d9}}
        pop {{r0-r4, lr}}
        bx lr
    """, addr=aim_entry, as_bytes=True)
    if aim_entry + len(aim_code) > AIM_PADDING_END:
        raise ValueError("Solo aim hook exceeds the verified NOP range")
    if CAVE + len(cave) > CONTROL_TAG_ADDRESS:
        raise ValueError("Remote hooks exceed the verified executable page padding")
    return {TICK: arm_branch(TICK, tick), QUEUE: arm_branch(QUEUE, queue),
            SET: arm_branch(SET, setter), CAVE: bytes(cave),
            TARGET_CAVE: target_code, TARGET_SELECT_CALL: arm_branch(
                TARGET_SELECT_CALL, TARGET_CAVE
            )[:3] + b"\x0b",
            AIM_PADDING: arm_branch(AIM_PADDING, AIM_PADDING_END) + aim_code,
            AIM_SELECT_CALL: arm_branch(AIM_SELECT_CALL, aim_entry)[:3] + b"\xeb",
            CONTROL_TAG_ADDRESS: SOLO_TARGET_CONTROL_TAG}


def build_patch():
    source = DUMP / "update-1.2/exefs/code.bin"
    code = source.read_bytes()
    for address, expected in ORIGINALS.items():
        if unpack_from("<I", code, address - IMAGE)[0] != expected:
            raise ValueError(f"Unexpected 1.2 hook instruction at {address:#x}")
    if unpack_from("<I", code, TARGET_SELECT_CALL - IMAGE)[0] != 0x0BFF14F1:
        raise ValueError("Unexpected 1.2 target selection call")
    if any(code[TARGET_CAVE - IMAGE:CAVE - IMAGE]):
        raise ValueError("Target selector padding does not match this 1.2 build")
    aim_call = arm_branch(AIM_SELECT_CALL, AIM_SELECT)[:3] + b"\xeb"
    if code[AIM_SELECT_CALL - IMAGE:AIM_SELECT_CALL - IMAGE + 4] != aim_call:
        raise ValueError("Unexpected 1.2 aim selection call")
    nop_range = code[AIM_PADDING - IMAGE:AIM_PADDING_END - IMAGE]
    if nop_range != pack("<I", 0xE1A00000) * (len(nop_range) // 4):
        raise ValueError("Solo aim NOP range does not match this 1.2 build")
    if any(code[CAVE - IMAGE:PAGE_END - IMAGE]):
        raise ValueError("Executable padding does not match this 1.2 build")
    records = build_records()
    exheader = source.with_name("exheader.bin").read_bytes()
    data_base, data_pages, _, bss_size = unpack_from("<IIII", exheader, 0x30)
    bss_base = data_base + data_pages * 4096
    allocated_end = bss_base + ((bss_size + 4095) & ~4095)
    if CONTROL_ADDRESS < bss_base + bss_size or CONTROL_ADDRESS + CONTROL_SIZE > allocated_end:
        raise ValueError("Control mailbox is outside page padding beyond the allocated globals")
    patch = bytearray(b"PATCH")
    for address, data in sorted(records.items()):
        patch.extend((address - IMAGE).to_bytes(3, "big"))
        patch.extend(len(data).to_bytes(2, "big"))
        patch.extend(data)
    patch.extend(b"EOF")
    destination = ROOT / "build/monster-remote-native/000400000011D700/exefs/code.ips"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(patch)
    print(f"Wrote {destination} with {len(records[CAVE])} bytes of native hooks.")


if __name__ == "__main__":
    build_patch()
