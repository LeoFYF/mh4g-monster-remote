"""Read MH4G 1.2 monster state and display it over Azahar or Citra on Windows."""

import argparse
import ctypes as ct
from ctypes import wintypes
from dataclasses import dataclass
from queue import Empty, SimpleQueue
import socket
from struct import Struct, iter_unpack, unpack_from
from threading import Event, Thread
from time import monotonic


RPC_PORT = 45987
HEADER = Struct("<4I")
READ_MEMORY = 1
PROCESS_LIST = 3
SELECT_PROCESS = 4
TITLE_ID = 0x000400000011D700
ENEMY_MANAGER = 0xF12214
ENEMY_SLOTS = 32
OBJECT_WORK = 0xE28
CODE_ADDRESS = 0x926C7C
CODE_SIGNATURE = bytes.fromhex("03cb80e230002de9280e90e58acf8ce2044b90e5000054e3")


class ReadError(Exception):
    pass


class Memory:
    """Select the 4G guest process and read its memory over localhost."""

    def __init__(self):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.connection.connect(("127.0.0.1", RPC_PORT))
        self.connection.settimeout(0.25)
        self.sequence = 0
        self.version = None

    def close(self):
        self.connection.close()

    def _request(self, version, kind, first, second, data=b""):
        self.sequence = (self.sequence + 1) & 0xFFFFFFFF
        header = HEADER.pack(version, self.sequence, kind, 8 + len(data))
        payload = first.to_bytes(4, "little") + second.to_bytes(4, "little") + data
        self.connection.send(header + payload)
        deadline = monotonic() + 0.25
        while monotonic() < deadline:
            self.connection.settimeout(max(0.001, deadline - monotonic()))
            packet = self.connection.recv(4096)
            if len(packet) < HEADER.size:
                continue
            reply_version, reply_id, reply_kind, length = HEADER.unpack_from(packet)
            if (reply_version, reply_id, reply_kind) != (version, self.sequence, kind):
                continue
            if len(packet) != HEADER.size + length:
                raise ReadError("调试接口返回的数据长度无效")
            return packet[HEADER.size:]
        raise ReadError("调试接口响应超时")

    def select_game(self, version):
        data = self._request(version, PROCESS_LIST, 0, 64)
        if not data:
            return
        if len(data) < 4:
            raise ReadError("调试接口返回的进程列表无效")
        count = unpack_from("<I", data)[0]
        if count > 64 or len(data) != 4 + count * 20:
            raise ReadError("调试接口返回的进程列表无效")
        for position in range(4, len(data), 20):
            pid, title_id = unpack_from("<IQ", data, position)
            if title_id == TITLE_ID:
                self._request(version, SELECT_PROCESS, 1, pid)
                return
        raise ReadError("等待《怪物猎人 4G》启动")

    def verify_game(self):
        versions = (self.version,) if self.version is not None else (1, 2)
        for version in versions:
            try:
                if self.version is None:
                    self.select_game(version)
                data = self._request(version, READ_MEMORY, CODE_ADDRESS, len(CODE_SIGNATURE))
            except (ReadError, OSError):
                continue
            if not data:
                continue
            if data != CODE_SIGNATURE:
                raise ReadError("等待《怪物猎人 4G》1.2")
            self.version = version
            return
        raise ReadError("等待模拟器 RPC")

    def read(self, address, size):
        blocks = []
        for start in range(0, size, 32):
            length = min(32, size - start)
            block = self._request(self.version, READ_MEMORY, address + start, length)
            if len(block) != length:
                raise ReadError("调试接口没有返回完整的内存数据")
            blocks.append(block)
        return b"".join(blocks)

    def pointer(self, address):
        return unpack_from("<I", self.read(address, 4))[0]


def valid_pointer(address):
    return 0x00100000 <= address < 0x40000000 and address % 4 == 0


@dataclass(frozen=True)
class Monster:
    slot: int
    script: str
    action: str
    state: str
    monster_id: int = 114
    identity: tuple = ()


class MonsterReader:
    def __init__(self, memory, monster_id):
        self.memory = memory
        self.monster_id = monster_id
        self.target = None
        self.check_again = 0

    def sample(self):
        manager = self.memory.pointer(ENEMY_MANAGER)
        if not valid_pointer(manager):
            self.target = None
            return None
        if self.target is not None and self.target[0] != manager:
            self.target = None
            self.check_again = 0
        if self.target is None and monotonic() >= self.check_again:
            self.find(manager)
        if self.target is None:
            return None
        sample = self.read_target(self.target)
        if sample is None or sample.monster_id != self.monster_id:
            self.target = None
            return None
        return sample

    def read_target(self, target):
        manager, slot, obj, work = target
        if (self.memory.pointer(manager + 0x18 + 4 * slot) != obj
                or self.memory.pointer(obj + OBJECT_WORK) != work):
            return None
        action = self.memory.read(work + 0x1C0, 12)
        monster_id = action[0]
        vm = self.memory.read(work + 0xB08, 6)
        ailment = self.memory.read(work + 0x530, 11)
        apex = self.memory.read(work + 0x7E80, 1)[0] & 0x20
        if self.memory.pointer(manager + 0x18 + 4 * slot) != obj:
            return None
        script = f"G{vm[4]}/S{vm[5]}" if unpack_from("<I", vm)[0] else "—"
        states = []
        if monster_id in (48, 114):
            states.append("带电" if self.memory.read(work + 0x7E6B, 1)[0] else "未带电")
        if ailment[0] == 1:
            states.append("发怒")
        elif ailment[0] == 2:
            states.append("疲劳")
        if apex:
            states.append("极限")
        elif ailment[10]:
            states.append("狂龙标记")
        states.append(f"状态 {action[8]:02X}")
        return Monster(slot, script, f"{action[10]:X}/{action[11]:02X}", " · ".join(states),
                       monster_id, (*target, monster_id))

    def targets(self, monster_ids):
        manager = self.memory.pointer(ENEMY_MANAGER)
        if not valid_pointer(manager):
            return ()
        slots = self.memory.read(manager + 0x18, ENEMY_SLOTS * 4)
        targets = []
        for slot, (obj,) in enumerate(iter_unpack("<I", slots)):
            if not valid_pointer(obj):
                continue
            work = self.memory.pointer(obj + OBJECT_WORK)
            if valid_pointer(work):
                monster_id = self.memory.read(work + 0x1C0, 1)[0]
                if monster_id in monster_ids:
                    targets.append((manager, slot, obj, work, monster_id))
        return tuple(targets)

    def find(self, manager):
        self.target = None
        self.check_again = monotonic() + 0.75
        slots = self.memory.read(manager + 0x18, ENEMY_SLOTS * 4)
        for slot in range(ENEMY_SLOTS):
            obj = unpack_from("<I", slots, slot * 4)[0]
            if valid_pointer(obj):
                work = self.memory.pointer(obj + OBJECT_WORK)
                if valid_pointer(work) and self.memory.read(work + 0x1C0, 1)[0] == self.monster_id:
                    self.target = manager, slot, obj, work
                    return


def observe(monster_id, publish, stop):
    while not stop.is_set():
        memory = Memory()
        try:
            reader = MonsterReader(memory, monster_id)
            verify_at = 0
            while not stop.is_set():
                if monotonic() >= verify_at:
                    memory.verify_game()
                    verify_at = monotonic() + 2
                publish(reader.sample())
                stop.wait(0.075)
        except (ReadError, OSError) as error:
            publish(str(error) if isinstance(error, ReadError) else "等待模拟器 RPC")
            stop.wait(0.75)
        finally:
            memory.close()


def wrap_action_name(name, font, width):
    from PySide6.QtGui import QTextLayout, QTextOption

    layout = QTextLayout(name, font)
    option = QTextOption()
    option.setWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
    layout.setTextOption(option)
    # Qt reports UTF-16 offsets, including for names that contain emoji.
    encoded = name.encode("utf-16-le")
    lines = []
    layout.beginLayout()
    while (line := layout.createLine()).isValid():
        line.setLineWidth(width)
        start = line.textStart() * 2
        end = start + line.textLength() * 2
        lines.append(encoded[start:end].decode("utf-16-le"))
    layout.endLayout()
    return "\n".join(lines)


def create_overlay(monster_id):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

    flags = (Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint
             | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.WindowTransparentForInput
             | Qt.WindowType.WindowDoesNotAcceptFocus)
    root = QWidget(None, flags)
    root.setObjectName("mh4gOverlay")
    root.setWindowTitle("MH4G Action Overlay")
    root.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
    root.setMinimumWidth(228)
    root.setStyleSheet(
        "QWidget#mh4gOverlay { background: #101720; border: 1px solid #41566F; }"
        "QLabel { font-family: 'Microsoft YaHei UI'; color: #A7C9B8; font-size: 13px; }"
        "QLabel#action { color: #F5F7FF; font-size: 19px; font-weight: 700; }"
    )
    layout = QVBoxLayout(root)
    layout.setContentsMargins(14, 8, 14, 8)
    layout.setSpacing(2)
    title = QLabel(f"MH4G  ·  em{monster_id:03}" if monster_id is not None else "MH4G", root)
    ids = QLabel("—", root)
    ids.setObjectName("action")
    detail = QLabel("", root)
    status = QLabel("等待模拟器 RPC", root)
    for label in (title, ids, detail, status):
        label.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(label)

    user32 = ct.WinDLL("user32")
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ct.c_int)
    user32.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ct.POINTER(wintypes.DWORD))
    user32.ClientToScreen.argtypes = (wintypes.HWND, ct.POINTER(wintypes.POINT))
    user32.IsIconic.argtypes = (wintypes.HWND,)
    user32.SetWindowPos.argtypes = (wintypes.HWND, wintypes.HWND, ct.c_int, ct.c_int,
                                    ct.c_int, ct.c_int, wintypes.UINT)
    hwnd = int(root.winId())
    previous_action = None

    def render(action, metadata, state, host_pid=0):
        nonlocal previous_action
        fg = user32.GetForegroundWindow()
        caption = ct.create_unicode_buffer(512)
        user32.GetWindowTextW(fg, caption, len(caption))
        foreground_pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(fg, ct.byref(foreground_pid))
        text = caption.value.lower()
        game_window = ("azahar" in text or "citra" in text) and "monster hunter 4g" in text
        if game_window and not user32.IsIconic(fg) and (not host_pid or host_pid == foreground_pid.value):
            origin = wintypes.POINT(12, 36)
            user32.ClientToScreen(fg, ct.byref(origin))
            # Use native pixel coordinates, including on mixed-DPI monitors.
            user32.SetWindowPos(hwnd, None, origin.x, origin.y, 0, 0, 0x15)
            if not root.isVisible():
                root.show()
            if action != previous_action:
                ids.setText(wrap_action_name(action, ids.font(), 350))
                previous_action = action
            detail.setText(metadata)
            detail.setVisible(bool(metadata))
            status.setText(state)
        elif root.isVisible():
            root.hide()

    return root, render


def overlay(monster_id):
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    app = QApplication([])
    app.setQuitOnLastWindowClosed(False)
    root, render = create_overlay(monster_id)
    samples = SimpleQueue()
    stop = Event()
    Thread(target=observe, args=(monster_id, samples.put, stop), daemon=True).start()
    info = "等待模拟器 RPC"

    def refresh():
        nonlocal info
        try:
            while True:
                info = samples.get_nowait()
        except Empty:
            pass
        if isinstance(info, Monster):
            render(info.action, info.script, info.state)
        else:
            render("—", "", info or f"等待 em{monster_id:03} 出现")

    timer = QTimer(root)
    timer.timeout.connect(refresh)
    timer.start(75)
    try:
        app.exec()
    finally:
        stop.set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--monster", type=int, choices=(48, 49, 114), default=114)
    parser.add_argument("--once", action="store_true", help="Sample the running game once.")
    args = parser.parse_args()
    if not args.once:
        overlay(args.monster)
        return
    memory = Memory()
    try:
        memory.verify_game()
        info = MonsterReader(memory, args.monster).sample()
        print(info or f"Connected to MH4G 1.2 (RPC v{memory.version}); em{args.monster:03} absent.")
    except (ReadError, OSError) as error:
        parser.exit(1, f"{error}\n")
    finally:
        memory.close()


if __name__ == "__main__":
    main()
