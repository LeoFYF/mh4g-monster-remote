"""Install the bundled control patch into a verified Windows emulator profile."""

import os
from pathlib import Path
from struct import pack
from tempfile import NamedTemporaryFile

from build_em114_lock import (
    AIM_PADDING, AIM_PADDING_END, AIM_SELECT, AIM_SELECT_CALL,
    CONTROL_TAG_ADDRESS, ORIGINALS, PAGE_END, SOLO_TARGET_CONTROL_TAG,
    TARGET_CAVE, TARGET_SELECT_CALL, arm_branch,
)
from emulator_detection import emulator_name, process_image
from mh4g_overlay import TITLE_ID


PATCH_PATH = Path("patch") / f"{TITLE_ID:016X}" / "exefs" / "code.ips"


def mods_directory(image, emulator, roaming):
    portable = image.parent / "user"
    profile = portable if portable.is_dir() else Path(roaming) / emulator
    if not profile.is_dir() or not (profile / "config").is_dir():
        raise OSError(f"找不到 {emulator} 的用户目录")
    return profile / "load" / "mods" / f"{TITLE_ID:016X}"


def publish_patch(mods, payload):
    if not payload.startswith(b"PATCH") or not payload.endswith(SOLO_TARGET_CONTROL_TAG + b"EOF"):
        raise ValueError("内置遥控补丁无效")
    exefs = mods / "exefs"
    destination = exefs / "code.ips"
    if destination.is_file() and destination.read_bytes() == payload:
        return "installed"
    if exefs.is_dir() and any(exefs.iterdir()):
        return "conflict"
    exefs.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with NamedTemporaryFile(dir=exefs, prefix=".mh4g-remote-", delete=False) as output:
            temporary = Path(output.name)
            output.write(payload)
        try:
            # On Windows, rename is atomic and cannot overwrite an existing file.
            os.rename(temporary, destination)
        except FileExistsError:
            return "installed" if destination.read_bytes() == payload else "conflict"
        return "new"
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def expected_code(memory):
    instructions = {**ORIGINALS, TARGET_SELECT_CALL: 0x0BFF14F1}
    return (
        all(memory.pointer(address) == word for address, word in instructions.items())
        and memory.read(AIM_SELECT_CALL, 4) == arm_branch(AIM_SELECT_CALL, AIM_SELECT)[:3] + b"\xeb"
        and memory.read(TARGET_CAVE, PAGE_END - TARGET_CAVE) == bytes(PAGE_END - TARGET_CAVE)
        and memory.read(AIM_PADDING, AIM_PADDING_END - AIM_PADDING)
        == pack("<I", 0xE1A00000) * ((AIM_PADDING_END - AIM_PADDING) // 4)
    )


def patch_location(emulator, resource_directory):
    image = process_image(emulator.pid)
    if emulator_name(image.name) != emulator.name:
        raise OSError("模拟器进程已改变")
    roaming = os.environ.get("APPDATA")
    if not roaming:
        raise OSError("找不到 Windows 用户配置目录")
    mods = mods_directory(image, emulator.name, roaming)
    source = resource_directory / PATCH_PATH
    if not source.is_file():
        source = resource_directory / "build" / "monster-remote-native" / PATCH_PATH.relative_to("patch")
    return mods, source.read_bytes()


def patch_status(mods, payload):
    exefs = mods / "exefs"
    destination = exefs / "code.ips"
    if destination.is_file() and destination.read_bytes() == payload:
        return "installed"
    if exefs.exists() and (not exefs.is_dir() or any(exefs.iterdir())):
        return "conflict"
    return "missing"


def change_patch(memory, mods, payload, install):
    state = patch_status(mods, payload)
    if install and state == "missing":
        if memory.read(CONTROL_TAG_ADDRESS, 4) != bytes(4) or not expected_code(memory):
            return "当前游戏代码无法核对。请重新启动 4G 后再安装"
        if publish_patch(mods, payload) == "conflict":
            return "目录已有其他 ExeFS 文件"
        return "补丁已安装。重新启动 4G 后生效"
    if not install and state == "installed":
        (mods / "exefs" / "code.ips").unlink()
        return "补丁已卸载。重新启动 4G 后生效"
    return "未改动文件。请查看当前补丁状态"
