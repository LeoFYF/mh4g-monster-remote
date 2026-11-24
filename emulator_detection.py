"""Detect which running Windows emulator owns the local 4G RPC port."""

import ctypes as ct
from ctypes import wintypes
from dataclasses import dataclass
from socket import AF_INET, ntohs
from struct import Struct


UDP_TABLE_OWNER_PID = 1
INSUFFICIENT_BUFFER = 122
INVALID_HANDLE = ct.c_void_p(-1).value
UDP_ROW = Struct("<III")


class ProcessEntry(ct.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("usage", wintypes.DWORD),
        ("pid", wintypes.DWORD),
        ("heap", ct.c_size_t),
        ("module", wintypes.DWORD),
        ("threads", wintypes.DWORD),
        ("parent", wintypes.DWORD),
        ("priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
        ("filename", wintypes.WCHAR * 260),
    ]


@dataclass(frozen=True)
class Emulator:
    name: str
    pid: int


def emulator_name(filename):
    name = filename.casefold()
    if name in ("azahar.exe", "azahar-qt.exe"):
        return "Azahar"
    if name in ("citra.exe", "citra-qt.exe", "citra-canary.exe", "citra-nightly.exe"):
        return "Citra"
    return ""


def running_emulators():
    kernel = ct.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    first, next_process = kernel.Process32FirstW, kernel.Process32NextW
    for function in (first, next_process):
        function.argtypes = (wintypes.HANDLE, ct.POINTER(ProcessEntry))
        function.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == INVALID_HANDLE:
        raise ct.WinError(ct.get_last_error())
    try:
        found = {}
        entry = ProcessEntry(size=ct.sizeof(ProcessEntry))
        if first(snapshot, ct.byref(entry)):
            while True:
                name = emulator_name(entry.filename)
                if name:
                    found[entry.pid] = Emulator(name, entry.pid)
                if not next_process(snapshot, ct.byref(entry)):
                    break
        return found
    finally:
        kernel.CloseHandle(snapshot)


def rpc_owners(port):
    read_table = ct.WinDLL("iphlpapi").GetExtendedUdpTable
    read_table.argtypes = (ct.c_void_p, ct.POINTER(wintypes.DWORD), wintypes.BOOL,
                           wintypes.ULONG, ct.c_int, wintypes.ULONG)
    read_table.restype = wintypes.DWORD
    size = wintypes.DWORD()
    buffer = None
    for _ in range(4):
        result = read_table(buffer, ct.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
        if result == 0:
            break
        if result != INSUFFICIENT_BUFFER:
            raise ct.WinError(result)
        buffer = ct.create_string_buffer(size.value)
    else:
        raise OSError("本机 RPC 端口列表持续变化")
    if buffer is None or size.value < 4:
        return set()
    data = buffer.raw[:size.value]
    count = int.from_bytes(data[:4], "little")
    count = min(count, (len(data) - 4) // UDP_ROW.size)
    return {
        pid for address, network_port, pid in UDP_ROW.iter_unpack(data[4:4 + count * UDP_ROW.size])
        if address in (0, 0x0100007F) and ntohs(network_port & 0xFFFF) == port
    }


def select_emulator(emulators, owners):
    names = " / ".join(sorted({emulator.name for emulator in emulators.values()}))
    if not names:
        return None, "", "等待启动 Azahar 或 Citra"
    if not owners:
        return None, names, "已检测到模拟器。打开 4G，并在模拟器的调试设置中启用 RPC。"
    if len(owners) != 1:
        return None, names, "本机 RPC 端口有多个监听进程，请只保留一个模拟器的 RPC。"
    emulator = emulators.get(next(iter(owners)))
    if emulator is None:
        return None, names, "本机 RPC 端口由其他程序占用。"
    return emulator, emulator.name, "等待 4G 1.2 连接"
