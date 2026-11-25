"""Single-action controller for MH4G 1.2 em114."""

import argparse
from collections import deque
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
import json
from pathlib import Path
from queue import Empty, SimpleQueue
from struct import pack
import sys
from threading import Event, Lock, Thread
from time import monotonic

from build_em114_lock import (
    CANCEL_CONTROL_TAG, RECOVERY_CONTROL_TAG, SOLO_TARGET_CONTROL_TAG, TARGET_CONTROL_TAG,
    TARGET_MODE_OFFSET,
    CAVE, CAVE_SIGNATURE, CONTROL_ADDRESS, CONTROL_SIZE, CONTROL_TAG, CONTROL_TAG_ADDRESS,
    EXPANDED_CONTROL_TAG, LEGACY_CAVE, LEGACY_CAVE_SIGNATURE, LEGACY_CONTROL_TAG, LEGACY_TICK,
    FIGHT_STATE_COMMAND, PAGE_END, QUEUE, SET, STATE_CONTROL_TAG, TICK,
)
from build_em114_round import localized_monster_names, monster_action_catalog
from emulator_detection import rpc_owners, running_emulators, select_emulator
from patch_installation import change_patch, patch_location, patch_status
from mh4g_overlay import (
    ENEMY_MANAGER, OBJECT_WORK, RPC_PORT, Memory, MonsterReader, ReadError, create_overlay,
    wrap_action_name,
)


REMOTE_ID = 114
WRITE_MEMORY = 2
RESOURCE_DIRECTORY = Path(__file__).resolve().parent
SETTINGS_DIRECTORY = Path(sys.executable).parent if getattr(sys, "frozen", False) else RESOURCE_DIRECTORY
NAMES_PATH = SETTINGS_DIRECTORY / "mh4g_remote_names.ini"
ICON_PATH = RESOURCE_DIRECTORY / "mh4g_remote.ico"
PROJECT_LINK_PATH = SETTINGS_DIRECTORY / "github-project.txt"
PROJECT_AUTHOR = "花露水企鹅"
MONSTER_DISPLAY_NAMES = {
    24: "蛇王龙上半身",
    77: "黑龙",
    78: "红黑龙",
    79: "祖龙",
    82: "锈钢龙",
    83: "蛇王龙下半身",
    97: "混沌黑蚀龙",
    98: "临界碎龙",
    110: "蛇帝龙上半身",
    111: "蛇帝龙下半身",
    112: "极限金狮子",
    113: "极限恐暴龙",
    114: "极限雷狼龙",
    115: "极限铠龙",
    117: "红焰龙",
    119: "极限角龙",
    120: "极限水蛇龙",
    121: "极限轰龙",
    122: "极限千刃龙",
}
QUEUE_LIMIT = 5
FIGHT_STATE_NAMES = ("普通", "怒", "疲劳")
SHARED_CONTROL_TAGS = (CONTROL_TAG, STATE_CONTROL_TAG, CANCEL_CONTROL_TAG, RECOVERY_CONTROL_TAG,
                       TARGET_CONTROL_TAG, SOLO_TARGET_CONTROL_TAG)
TARGET_MODES = ("恢复原生", "不锁定", "玩家 1", "玩家 2", "玩家 3", "玩家 4")
SUPPORTED_CONTROL_TAGS = (*SHARED_CONTROL_TAGS, EXPANDED_CONTROL_TAG, LEGACY_CONTROL_TAG)


def action_name(action):
    if action[0] == FIGHT_STATE_COMMAND and action[1] < len(FIGHT_STATE_NAMES):
        return FIGHT_STATE_NAMES[action[1]]
    return f"{action[0]:X}/{action[1]:02X}"


@dataclass(frozen=True)
class Status:
    message: str
    action: str = "—"
    phase: str = ""
    script: str = "—"
    ready: bool = False
    repeating_ready: bool = False
    expanded_actions: bool = False
    fight_state_control: bool = False
    target_control: bool = False
    target_mode: int = 0
    hunter_slot: int = 255
    lock_available: bool = False
    locked: bool = False
    staged: bytes | None = None
    emulator: str = ""
    host_pid: int = 0
    patch_disk: str = ""
    patch_loaded: bool = False
    targets: tuple = ()
    selected: tuple | None = None
    reaction_numbers: tuple = ()


@dataclass(frozen=True)
class LockRequest:
    enabled: bool


@dataclass(frozen=True)
class TargetRequest:
    monster: tuple
    mode: int


@dataclass(frozen=True)
class PatchRequest:
    pid: int
    install: bool


class ActionQueue:
    def __init__(self):
        self._items = deque()
        self._staged = None
        self._last = None
        self._repeat = None
        self._lock = Lock()

    def append(self, action):
        with self._lock:
            if len(self._items) + (self._staged is not None) >= QUEUE_LIMIT:
                return False
            self._items.append(action)
            return True

    def take(self, repeating_ready=False):
        with self._lock:
            if self._staged is not None:
                return None
            if self._items:
                self._staged = self._items.popleft()
                return self._staged, False
            if repeating_ready and self._repeat is not None:
                return self._repeat, True
            return None

    def sent(self, action, repeating):
        if not repeating:
            with self._lock:
                self._last = action

    def set_repeat(self, enabled):
        with self._lock:
            self._repeat = self._last if enabled else None

    def repeat_status(self):
        with self._lock:
            return self._last, self._repeat

    def confirm_staged(self, action):
        with self._lock:
            self._staged = action

    def clear(self):
        with self._lock:
            self._items.clear()
            self._staged = None
            self._last = None
            self._repeat = None

    def snapshot(self):
        with self._lock:
            pending = (self._staged,) if self._staged is not None else ()
            return pending + tuple(self._items)


class Remote:
    def __init__(self, memory, catalog, emulator=None, reactions=None):
        self.memory = memory
        self.catalog = catalog
        self.reader = MonsterReader(memory, REMOTE_ID)
        self.emulator = emulator
        self.targets = ()
        self.target = None
        self.scan_at = 0
        self.reactions = reactions or {}
        self.observed_reactions = {}

    def monster_reactions(self, monster):
        obj = monster.identity[2]
        vtable = self.memory.pointer(obj)
        entry = self.memory.pointer(vtable + 0xB0) if 0x00100000 <= vtable < 0x01000000 else 0
        key = monster.monster_id, entry
        observed = self.observed_reactions.setdefault(key, set())
        category, number = monster.action.split("/")
        if category == "A":
            observed.add(int(number, 16))
        return tuple(sorted(observed.union(self.reactions.get(entry, ()))))

    def scan_targets(self):
        self.targets = self.reader.targets(self.catalog)
        if self.target not in self.targets:
            self.target = next((target for target in self.targets if target[-1] == REMOTE_ID),
                               self.targets[0] if self.targets else None)
        self.scan_at = monotonic() + 0.6

    @property
    def emulator_name(self):
        return self.emulator.name if self.emulator else "模拟器"

    def missing_patch(self, component):
        return f"{self.emulator_name} 未加载{component}。退出 4G 并重新启动游戏后再进任务。"

    def mailbox(self):
        tag = self.control_tag()
        if tag not in SUPPORTED_CONTROL_TAGS:
            return None
        if tag in SHARED_CONTROL_TAGS:
            signatures = ((CAVE, CAVE_SIGNATURE),)
            tick = TICK
        else:
            signatures = ((CAVE, LEGACY_CAVE_SIGNATURE), (LEGACY_CAVE, LEGACY_CAVE_SIGNATURE))
            tick = LEGACY_TICK
        if (any(self.memory.read(address, len(signature)) == signature
                for address, signature in signatures)
                and all(self._branches_to_cave(address) for address in (tick, QUEUE, SET))):
            return CONTROL_ADDRESS
        return None

    def has_control_tag(self):
        return self.control_tag() in SUPPORTED_CONTROL_TAGS

    def control_tag(self):
        return self.memory.read(CONTROL_TAG_ADDRESS, len(CONTROL_TAG))

    @staticmethod
    def owner(target):
        return pack("<II", target[2], target[3])

    def _branches_to_cave(self, address):
        instruction = self.memory.pointer(address)
        offset = instruction & 0xFFFFFF
        if offset & 0x800000:
            offset -= 0x1000000
        return instruction >> 24 == 0xEA and LEGACY_CAVE <= address + 8 + offset * 4 < PAGE_END

    def confirmed_target(self):
        if self.target is None:
            raise ReadError("当前没有可遥控的怪物")
        manager, slot, obj, work, monster_id = self.target
        if (self.memory.pointer(ENEMY_MANAGER) != manager
                or self.memory.pointer(manager + 0x18 + slot * 4) != obj
                or self.memory.pointer(obj + OBJECT_WORK) != work
                or self.memory.read(work + 0x1C0, 1) != bytes((monster_id,))):
            raise ReadError("怪物对象已经改变")
        return work

    def snapshot(self):
        if monotonic() >= self.scan_at:
            self.scan_targets()
        monster = self.reader.read_target(self.target[:4]) if self.target else None
        target_details = {"targets": self.targets, "selected": self.target}
        if monster is None:
            return Status("等待任务中的怪物", **target_details)
        if monster.identity != self.target:
            return Status("怪物对象已经改变", **target_details)
        details = dict(target_details, action=monster.action, phase=monster.state, script=monster.script)
        details["reaction_numbers"] = self.monster_reactions(monster)
        details["hunter_slot"] = self.memory.read(self.target[3] + 0x1DA, 1)[0]
        address = self.mailbox()
        if address is None:
            return Status(self.missing_patch("遥控程序补丁"), **details)
        tag = self.control_tag()
        if monster.monster_id != REMOTE_ID and tag not in SHARED_CONTROL_TAGS:
            return Status("可读取状态，手动出招需要通用补丁", **details)
        if not self.catalog[monster.monster_id]:
            return Status("已读取状态，资源中没有动作请求", **details)
        details["expanded_actions"] = tag != LEGACY_CONTROL_TAG
        details["fight_state_control"] = tag in (STATE_CONTROL_TAG, CANCEL_CONTROL_TAG,
                                                 RECOVERY_CONTROL_TAG, TARGET_CONTROL_TAG,
                                                 SOLO_TARGET_CONTROL_TAG)
        details["target_control"] = tag in (TARGET_CONTROL_TAG, SOLO_TARGET_CONTROL_TAG)
        control = self.memory.read(address, CONTROL_SIZE)
        if control[8:16] != self.owner(self.target):
            return Status("原版 AI 自主行动中，可手动点招", ready=True, lock_available=True, **details)
        enabled, requested, category, action, accepted, mode = control[:6]
        if details["target_control"] and control[TARGET_MODE_OFFSET] < len(TARGET_MODES):
            details["target_mode"] = control[TARGET_MODE_OFFSET]
        locked = bool(enabled)
        staged = bytes((category, action)) if requested != accepted else None
        if mode in (2, 3, 4):
            message = "正在执行手动连段" if locked else "正在执行手动招式，结束后交回 AI"
        elif staged:
            message = f"等待执行 {action_name(staged)}"
        elif locked and mode == 1:
            message = "已禁止自主动作，可手动出招"
        elif locked:
            message = "正在停止自主动作"
        else:
            message = "原版 AI 自主行动中，可手动点招"
        return Status(message, ready=staged is None,
                      repeating_ready=staged is None and mode in (0, 1),
                      lock_available=True, locked=locked, staged=staged, **details)

    def write_control(self, address, data):
        if not CONTROL_ADDRESS <= address <= CONTROL_ADDRESS + CONTROL_SIZE - len(data):
            raise ReadError("遥控指令超出控制区")
        if not self.has_control_tag():
            raise ReadError("RPC 修复补丁未加载，请重启游戏")
        if self.emulator and rpc_owners(RPC_PORT) != {self.emulator.pid}:
            raise ReadError("模拟器已切换，未发送遥控指令")
        self.memory._request(self.memory.version, WRITE_MEMORY, address, len(data), data)
        actual = self.memory.read(address, len(data))
        if actual != data:
            raise ReadError(f"{self.emulator_name} 未写入遥控指令，请重启已安装补丁的 4G")

    def bind_control(self):
        self.confirmed_target()
        address = self.mailbox()
        if address is None:
            raise ReadError(self.missing_patch("遥控程序补丁"))
        control = self.memory.read(address, CONTROL_SIZE)
        owner = self.owner(self.target)
        if control[8:16] != owner:
            # Disable dispatch before assigning a new owner, and publish it last.
            self.write_control(address, bytes(8))
            self.write_control(address + 16, bytes(4))
            self.write_control(address + 8, owner)
            control = self.memory.read(address, CONTROL_SIZE)
        return address, control

    def set_lock(self, enabled):
        target = self.target
        state = self.snapshot()
        if not state.lock_available or self.target != target:
            raise ReadError(state.message)
        address, control = self.bind_control()
        if bool(control[0]) != enabled:
            self.write_control(address, bytes((int(enabled),)))

    def set_target_mode(self, request):
        status = self.snapshot()
        if (not status.target_control or self.target != request.monster
                or not 0 <= request.mode < len(TARGET_MODES)):
            raise ReadError("当前怪物无法切换目标")
        address, control = self.bind_control()
        if control[TARGET_MODE_OFFSET] != request.mode:
            self.write_control(address + TARGET_MODE_OFFSET, bytes((request.mode,)))

    def release_owner(self, target):
        if target is None or not self.has_control_tag():
            return
        control = self.memory.read(CONTROL_ADDRESS, CONTROL_SIZE)
        if control[8:16] == self.owner(target):
            self.write_control(CONTROL_ADDRESS, bytes(4))
            self.write_control(CONTROL_ADDRESS + 8, bytes(8))

    def send_action(self, action):
        target = self.target
        info = self.snapshot()
        state_request = action[0] == FIGHT_STATE_COMMAND
        supported = (info.fight_state_control and action[1] < len(FIGHT_STATE_NAMES)
                     if state_request else target is not None and (
                         action in self.catalog[target[-1]]
                         or action[0] == 0xA and action[1] in info.reaction_numbers
                     ))
        if (target is None or self.target != target
                or not supported or not info.ready):
            raise ReadError("游戏正在接收上一条指令")
        if not info.expanded_actions and action[0] not in (2, 3, 7):
            raise ReadError("这个动作需要更新遥控程序补丁")
        address, control = self.bind_control()
        if control[1] != control[4] or control[8:16] != self.owner(self.target):
            raise ReadError("游戏正在接收上一条指令")
        self.write_control(address, bytes((control[0], (control[1] + 1) & 0xFF, *action)))


def watch(actions, reactions, outgoing, moves, updates, done):
    while not done.is_set():
        emulator = None
        name = ""
        memory = None
        try:
            emulator, name, message = select_emulator(running_emulators(), rpc_owners(RPC_PORT))
            if emulator is None:
                updates.put(Status(message, emulator=name))
                done.wait(0.75)
                continue
            memory = Memory()
            memory.verify_game()
            controller = Remote(memory, actions, emulator, reactions)
            verify_at = monotonic() + 2
            target = None

            def inspect_patch():
                try:
                    mods, payload = patch_location(emulator, RESOURCE_DIRECTORY)
                    return patch_status(mods, payload)
                except OSError:
                    return "unknown"

            disk_patch = inspect_patch()

            def publish(state):
                updates.put(replace(state, emulator=emulator.name, host_pid=emulator.pid,
                                    patch_disk=disk_patch, patch_loaded=controller.has_control_tag()))

            while not done.is_set():
                if monotonic() >= verify_at:
                    if rpc_owners(RPC_PORT) != {emulator.pid}:
                        raise ReadError("模拟器已切换，正在重新连接")
                    memory.verify_game()
                    disk_patch = inspect_patch()
                    verify_at = monotonic() + 2
                try:
                    request = outgoing.get_nowait()
                except Empty:
                    request = None
                if isinstance(request, tuple):
                    if request in controller.targets:
                        controller.target = request
                elif isinstance(request, PatchRequest):
                    if request.pid == emulator.pid and rpc_owners(RPC_PORT) == {emulator.pid}:
                        memory.verify_game()
                        try:
                            mods, payload = patch_location(emulator, RESOURCE_DIRECTORY)
                            message = change_patch(memory, mods, payload, request.install)
                        except (OSError, ValueError) as error:
                            message = f"无法修改遥控补丁：{error}"
                        disk_patch = inspect_patch()
                        publish(replace(controller.snapshot(), message=message))
                        done.wait(1.5)
                elif request is not None:
                    try:
                        if isinstance(request, TargetRequest):
                            controller.set_target_mode(request)
                        else:
                            controller.set_lock(request.enabled)
                    except ReadError as error:
                        state = controller.snapshot()
                        publish(replace(state, message=str(error)))
                        done.wait(1)
                state = controller.snapshot()
                if controller.target != target:
                    controller.release_owner(target)
                    moves.clear()
                elif not state.lock_available:
                    moves.clear()
                target = controller.target
                moves.confirm_staged(state.staged)
                if state.ready:
                    selection = moves.take(state.repeating_ready)
                    if selection is not None:
                        action, repeating = selection
                        try:
                            controller.send_action(action)
                            if action[0] != FIGHT_STATE_COMMAND:
                                moves.sent(action, repeating)
                            state = controller.snapshot()
                        except ReadError as error:
                            state = controller.snapshot()
                            state = replace(state, message=str(error))
                            publish(state)
                            done.wait(1)
                        moves.confirm_staged(state.staged)
                publish(state)
                done.wait(0.12)
        except (OSError, ReadError) as error:
            moves.clear()
            updates.put(Status(str(error) if isinstance(error, ReadError) else "等待模拟器 RPC",
                               emulator=name))
            try:
                outgoing.get_nowait()
            except Empty:
                pass
            done.wait(0.75)
        finally:
            if memory is not None:
                memory.close()


def show_ui(actions, monster_names, reactions):
    from ctypes import c_wchar_p, windll

    from PySide6.QtCore import QSettings, Qt, QTimer, QUrl
    from PySide6.QtGui import QDesktopServices, QIcon
    from PySide6.QtWidgets import (
        QApplication, QComboBox, QDialog, QGridLayout, QHBoxLayout, QInputDialog,
        QLabel, QLineEdit, QMenu, QMessageBox,
        QPushButton, QScrollArea, QTabBar, QToolButton, QVBoxLayout, QWidget,
    )

    set_app_id = windll.shell32.SetCurrentProcessExplicitAppUserModelID
    set_app_id.argtypes = (c_wchar_p,)
    set_app_id("MH4G.Em114.Remote")
    app = QApplication([])
    app.setWindowIcon(QIcon(str(ICON_PATH)))
    names = QSettings(str(NAMES_PATH), QSettings.Format.IniFormat)
    window = QWidget()
    window.setWindowTitle("4G · 怪物遥控器")
    window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint,
                         names.value("ui/always-on-top", True, type=bool))
    window.resize(420, 565)
    window.setStyleSheet(
        "QWidget { background: #101720; color: #e7eef8; font: 13px 'Microsoft YaHei UI'; }"
        "QLabel#title { font-size: 20px; font-weight: bold; }"
        "QLabel#status { color: #9adbc6; }"
        "QLineEdit { background: #182435; border: 1px solid #3d536c; padding: 8px; }"
        "QPushButton, QToolButton { background: #203147; border: 1px solid #4c6683;"
        " border-radius: 5px; padding: 8px; }"
        "QPushButton:hover { background: #34516d; }"
        "QPushButton:checked { background: #27614f; border-color: #79c5a9; }"
        "QPushButton[waiting=true], QPushButton:disabled { background: #16212f; color: #8393a8; }"
        "QScrollArea { border: 0; }"
    )
    layout = QVBoxLayout(window)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(8)
    title = QLabel("怪物遥控器")
    title.setObjectName("title")
    try:
        link_path = PROJECT_LINK_PATH if PROJECT_LINK_PATH.is_file() else RESOURCE_DIRECTORY / "github-project.txt"
        project_url = QUrl(link_path.read_text(encoding="utf-8").strip())
    except (OSError, UnicodeError):
        project_url = QUrl()
    parts = project_url.path().strip("/").split("/")
    has_project_url = (project_url.isValid() and project_url.scheme() == "https"
                       and project_url.host() == "github.com" and len(parts) == 2
                       and all(parts) and not project_url.userInfo())

    def open_project():
        if has_project_url:
            QDesktopServices.openUrl(project_url)

    def show_about():
        dialog = QMessageBox(window)
        dialog.setWindowTitle("关于此软件")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText("怪物猎人 4G · 怪物遥控器")
        dialog.setInformativeText(f"作者：{PROJECT_AUTHOR}\n本软件由 AI 协助开发。")
        dialog.setStandardButtons(QMessageBox.StandardButton.Close)
        project = dialog.addButton("打开 GitHub 项目" if has_project_url else "GitHub 项目待发布",
                                   QMessageBox.ButtonRole.ActionRole)
        project.setEnabled(has_project_url)
        project.clicked.connect(open_project)
        dialog.exec()

    menu_button = QToolButton()
    menu_button.setText("菜单")
    menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
    menu = QMenu(menu_button)
    preferences = menu.addMenu("设置")
    patch_menu = menu.addMenu("通用补丁")
    patch_state = patch_menu.addAction("等待 4G 连接")
    patch_state.setEnabled(False)
    install_patch = patch_menu.addAction("安装通用补丁")
    uninstall_patch = patch_menu.addAction("卸载通用补丁")
    install_patch.setEnabled(False)
    uninstall_patch.setEnabled(False)
    top_option = preferences.addAction("主窗口置顶")
    top_option.setCheckable(True)
    top_option.setChecked(names.value("ui/always-on-top", True, type=bool))
    overlay_option = preferences.addAction("显示动作叠加层")
    overlay_option.setCheckable(True)
    overlay_option.setChecked(names.value("ui/show-overlay", True, type=bool))

    def change_top(enabled):
        names.setValue("ui/always-on-top", enabled)
        window.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, enabled)
        window.show()

    top_option.toggled.connect(change_top)
    overlay_option.toggled.connect(lambda enabled: names.setValue("ui/show-overlay", enabled))
    menu.addAction("关于此软件", show_about)
    project_action = menu.addAction("打开 GitHub 项目", open_project)
    project_action.setEnabled(has_project_url)
    menu_button.setMenu(menu)
    toolbar = QHBoxLayout()
    toolbar.addWidget(title, 1)
    toolbar.addWidget(menu_button)
    layout.addLayout(toolbar)
    current = QLabel("当前动作 —")
    current.setTextFormat(Qt.TextFormat.PlainText)
    current.setWordWrap(True)
    connection = QLabel("未连接模拟器")
    status = QLabel("等待启动 Azahar 或 Citra")
    status.setObjectName("status")
    status.setWordWrap(True)
    lock = QPushButton("禁止自主动作")
    lock.setCheckable(True)
    lock.setEnabled(False)
    lock.setToolTip("锁定时只执行手动招式及其连段。关闭时空闲期间恢复原版 AI。")
    repeat = QPushButton("循环上一招")
    repeat.setCheckable(True)
    repeat.setEnabled(False)
    repeat.setToolTip("重复最近一次手动出招。再次点击停止，当前连段会执行完。")
    repeat_name = QLabel()
    repeat_name.setTextFormat(Qt.TextFormat.PlainText)
    repeat_name.setWordWrap(True)
    search = QLineEdit()
    search.setPlaceholderText("筛选动作编号或动作组")
    move_list = QLabel()
    move_list.setTextFormat(Qt.TextFormat.PlainText)
    move_list.setWordWrap(True)
    tabs = QTabBar()
    tabs.setExpanding(False)
    for item in (connection, tabs, current, status):
        layout.addWidget(item)
    controls = QHBoxLayout()
    controls.addWidget(lock)
    controls.addWidget(repeat)
    layout.addLayout(controls)
    layout.addWidget(repeat_name)
    layout.addWidget(move_list)
    states = QHBoxLayout()
    fight_state = QComboBox()
    fight_state.addItem("战斗状态")
    fight_state.addItems(FIGHT_STATE_NAMES)
    fight_state.setEnabled(False)
    special_state = QComboBox()
    special_state.addItems(("特殊状态", "带电", "未带电"))
    special_state.setEnabled(False)
    states.addWidget(fight_state)
    states.addWidget(special_state)
    layout.addLayout(states)
    target_label = QLabel("当前猎人目标 —")
    target_menu = QComboBox()
    target_menu.addItems(TARGET_MODES)
    target_menu.setEnabled(False)
    target_menu.setAccessibleName("仇恨目标")
    target_row = QHBoxLayout()
    target_row.addWidget(target_label)
    target_row.addWidget(target_menu)
    layout.addLayout(target_row)
    layout.addWidget(search)

    manager = QDialog(window, Qt.WindowType.Tool)
    manager.setWindowTitle("4G · 动作组")
    manager.setAttribute(Qt.WidgetAttribute.WA_QuitOnClose, False)
    manager.resize(355, 420)
    manager_layout = QVBoxLayout(manager)
    manager_layout.setContentsMargins(12, 12, 12, 12)
    selected_monster = QLabel("等待任务中的怪物")
    manager_layout.addWidget(selected_monster)
    name_row = QHBoxLayout()
    group_name_edit = QLineEdit()
    group_name_edit.setAccessibleName("动作组名称")
    rename_group_button = QPushButton("重命名")
    name_row.addWidget(group_name_edit, 1)
    name_row.addWidget(rename_group_button)
    manager_layout.addLayout(name_row)
    manager_layout.addWidget(QLabel("代码池"))

    grid_parent = QWidget()
    grid = QGridLayout(grid_parent)
    grid.setContentsMargins(0, 0, 5, 0)
    grid.setAlignment(Qt.AlignmentFlag.AlignTop)
    for column in range(3):
        grid.setColumnStretch(column, 1)
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setWidget(grid_parent)
    layout.addWidget(scroll)
    detail_parent = QWidget()
    detail_grid = QGridLayout(detail_parent)
    detail_grid.setAlignment(Qt.AlignmentFlag.AlignTop)
    detail_scroll = QScrollArea()
    detail_scroll.setWidgetResizable(True)
    detail_scroll.setWidget(detail_parent)
    manager_layout.addWidget(detail_scroll)

    def show_manager():
        if not manager.isVisible():
            screen = window.screen().availableGeometry()
            right = window.frameGeometry().right() + 8
            left = window.frameGeometry().left() - manager.width() - 8
            x = right if right + manager.width() <= screen.right() else max(screen.left(), left)
            y = max(screen.top(), min(window.y(), screen.bottom() - manager.height()))
            manager.move(x, y)
            manager.show()
        manager.raise_()
        manager.activateWindow()

    outgoing = SimpleQueue()
    moves = ActionQueue()
    updates = SimpleQueue()
    done = Event()
    buttons = {}
    group_headers = {}
    detail_group = None
    detail_controls = []
    latest = Status("等待启动 Azahar 或 Citra")
    switching = False
    pending_target = None
    shown_targets = ()
    shown_monster = None
    shown_reactions = ()
    overlay_window, render_overlay = create_overlay(None)

    def request_patch(install):
        expected = "missing" if install else "installed"
        if latest.host_pid and latest.patch_disk == expected:
            outgoing.put(PatchRequest(latest.host_pid, install))

    install_patch.triggered.connect(lambda: request_patch(True))
    uninstall_patch.triggered.connect(lambda: request_patch(False))

    def select_target(index):
        nonlocal switching, pending_target
        if 0 <= index < len(shown_targets) and shown_targets[index] != latest.selected:
            switching = True
            pending_target = shown_targets[index]
            moves.clear()
            lock.setEnabled(False)
            repeat.setEnabled(False)
            outgoing.put(pending_target)

    tabs.currentChanged.connect(select_target)

    def request_lock(enabled):
        nonlocal switching
        switching = True
        lock.setEnabled(False)
        status.setText("正在切换自主动作")
        outgoing.put(LockRequest(enabled))

    lock.clicked.connect(request_lock)

    def request_target(mode):
        if not switching and latest.target_control and latest.selected is not None:
            outgoing.put(TargetRequest(latest.selected, mode))

    target_menu.activated.connect(request_target)


    def name_namespace():
        return "actions" if shown_monster in (None, REMOTE_ID) else f"em{shown_monster:03}"

    def name_key(action):
        return f"{name_namespace()}/{action[0]:X}-{action[1]:02X}"

    def stored_groups():
        groups = defaultdict(list)
        prefix = name_namespace() + "/"
        for key in names.allKeys():
            if key.startswith(prefix):
                name = names.value(key, "", type=str)
                if name:
                    groups[name].append(key)
        return groups

    def saved_name(action):
        return names.value(name_key(action), "", type=str)

    def live_name(number):
        if number == "—":
            return ""
        return saved_name(bytes(int(part, 16) for part in number.split("/")))

    def set_action_buttons_ready(value):
        for button in buttons.values():
            if button.property("waiting") != (not value):
                button.setProperty("waiting", not value)
                button.style().unpolish(button)
                button.style().polish(button)

    def send(action):
        if switching or not latest.lock_available:
            return
        if not latest.expanded_actions and action[0] not in (2, 3, 7):
            return
        moves.append(action)
        display_queue()

    def choose_fight_state(index):
        fight_state.setCurrentIndex(0)
        if index > 0 and latest.fight_state_control:
            send(bytes((FIGHT_STATE_COMMAND, index - 1)))

    def choose_special_state(index):
        special_state.setCurrentIndex(0)
        if index in (1, 2) and shown_monster in (48, 114):
            send(bytes((1, index + 3)))

    fight_state.activated.connect(choose_fight_state)
    special_state.activated.connect(choose_special_state)

    def save_settings(changes):
        previous = {key: names.value(key, "", type=str) for key in changes}
        for key, value in changes.items():
            if value:
                names.setValue(key, value)
            else:
                names.remove(key)
        names.sync()
        if names.status() != QSettings.Status.NoError:
            for key, name in previous.items():
                if name:
                    names.setValue(key, name)
                else:
                    names.remove(key)
            parent = manager if manager.isVisible() else window
            QMessageBox.warning(parent, "保存失败", f"无法保存动作名称到\n{NAMES_PATH}")
            return False
        return True

    def save_groups(keys, value, previous_group=None):
        nonlocal detail_group
        namespace = keys[0].split("/", 1)[0]
        changes = dict.fromkeys(keys, value)
        if previous_group and previous_group != value:
            old_key = default_key(namespace, previous_group)
            new_key = default_key(namespace, value)
            old_default = names.value(old_key, "", type=str)
            if old_default and not names.value(new_key, "", type=str):
                changes[new_key] = old_default
            changes[old_key] = ""
        if not save_settings(changes):
            return
        if previous_group and detail_group == previous_group and namespace == name_namespace():
            detail_group = value
            group_name_edit.setText(value)
        filter_actions(search.text())
        display_current()
        display_queue()

    def edit_name(keys, title, previous):
        parent = manager if manager.isVisible() else window
        value, ok = QInputDialog.getText(parent, title, "动作组名称", text=previous)
        if ok and value.strip():
            save_groups(keys, value.strip())

    def default_key(namespace, name):
        return f"group-defaults/{namespace}/{name.encode('utf-8').hex()}"

    def group_default(name, members):
        chosen = names.value(default_key(name_namespace(), name), "", type=str)
        return next((action for action in members if action.hex() == chosen), members[0])

    def send_group(name):
        members = [action for action in buttons if saved_name(action) == name]
        if members:
            send(group_default(name, members))

    def action_menu(action, button, position):
        key = name_key(action)
        previous = saved_name(action)
        menu = QMenu(button)
        rename = menu.addAction("重命名")
        assign = menu.addMenu("归入动作组")
        choices = {}
        for group in sorted(stored_groups(), key=str.casefold):
            if group != previous:
                choices[assign.addAction(group.replace("&", "&&"))] = group
        assign.setEnabled(bool(choices))
        remove = menu.addAction("移出动作组") if previous else None
        picked = menu.exec(button.mapToGlobal(position))
        if picked is rename:
            edit_name((key,), f"重命名 {action_name(action)}", previous)
        elif picked in choices:
            save_groups((key,), choices[picked])
        elif remove is not None and picked is remove:
            save_groups((key,), "")

    def open_group(name):
        nonlocal detail_group
        detail_group = name
        group_name_edit.setText(name)
        filter_actions(search.text())
        show_manager()

    def rename_open_group():
        value = group_name_edit.text().strip()
        keys = tuple(stored_groups().get(detail_group, ()))
        if keys and value and value != detail_group:
            save_groups(keys, value, detail_group)

    def choose_default(action):
        if detail_group and saved_name(action) == detail_group:
            if save_settings({default_key(name_namespace(), detail_group): action.hex()}):
                filter_actions(search.text())

    def remove_member(action):
        if detail_group and saved_name(action) == detail_group:
            save_groups((name_key(action),), "")

    rename_group_button.clicked.connect(rename_open_group)
    group_name_edit.returnPressed.connect(rename_open_group)

    def populate(monster_id, reaction_numbers):
        for button in buttons.values():
            grid.removeWidget(button)
            button.hide()
            button.deleteLater()
        buttons.clear()
        available = set(actions.get(monster_id, ()))
        available.update(bytes((0xA, number)) for number in reaction_numbers)
        for action in sorted(available):
            button = QPushButton(action_name(action))
            button.setProperty("waiting", True)
            button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            button.customContextMenuRequested.connect(
                lambda pos, value=action, widget=button: action_menu(value, widget, pos)
            )
            button.clicked.connect(lambda _checked=False, value=action: send(value))
            buttons[action] = button
            button.setToolTip("右键重命名或归入动作组")
        filter_actions(search.text())

    def filter_actions(value):
        query = value.strip().casefold()
        grouped = defaultdict(list)
        ungrouped = []
        for action, button in buttons.items():
            grid.removeWidget(button)
            button.hide()
            if button.parentWidget() is not grid_parent:
                button.setParent(grid_parent)
            name = saved_name(action)
            if name:
                grouped[name].append(action)
            elif query in action_name(action).casefold():
                ungrouped.append(action)
        for name, header in list(group_headers.items()):
            grid.removeWidget(header)
            header.hide()
            if name not in grouped:
                del group_headers[name]
                header.deleteLater()

        count = 0
        for name, members in sorted(grouped.items(), key=lambda item: item[0].casefold()):
            matched = members if query in name.casefold() else [
                action for action in members if query in action_name(action).casefold()
            ]
            if not matched:
                continue
            if name not in group_headers:
                header = QPushButton()
                header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                header.customContextMenuRequested.connect(
                    lambda _pos, group=name: open_group(group)
                )
                header.clicked.connect(lambda _checked, group=name: send_group(group))
                group_headers[name] = header
            header = group_headers[name]
            full_name = wrap_action_name(name, header.font(), 108).replace("&", "&&")
            default = action_name(group_default(name, members))
            header.setText(f"{full_name}\n默认 {default}")
            header.setToolTip("左键执行默认代码，右键管理动作组")
            grid.addWidget(header, count // 3, count % 3)
            header.show()
            count += 1
        row = (count + 2) // 3
        for index, action in enumerate(ungrouped):
            grid.addWidget(buttons[action], row + index // 3, index % 3)
            buttons[action].show()
        for control in detail_controls:
            detail_grid.removeWidget(control)
            control.hide()
            control.deleteLater()
        detail_controls.clear()
        members = grouped.get(detail_group, ())
        if not members:
            manager.hide()
        else:
            default = group_default(detail_group, members)
            for index, action in enumerate(members):
                detail_grid.addWidget(buttons[action], index, 0)
                buttons[action].show()
                choose = QPushButton("默认" if action == default else "设为默认")
                choose.setEnabled(action != default)
                choose.clicked.connect(lambda _checked, value=action: choose_default(value))
                remove = QPushButton("移出")
                remove.clicked.connect(lambda _checked, value=action: remove_member(value))
                detail_grid.addWidget(choose, index, 1)
                detail_grid.addWidget(remove, index, 2)
                choose.show()
                remove.show()
                detail_controls.extend((choose, remove))

    search.textChanged.connect(filter_actions)
    filter_actions("")

    def display_current():
        name = live_name(latest.action)
        text = f"{name}  ({latest.action})" if name else latest.action
        state = f"   ·   {latest.phase}" if latest.phase else ""
        current.setText(f"当前动作 {text}{state}")
        metadata = f"{latest.action}  ·  {latest.script}" if name else latest.script
        if overlay_option.isChecked():
            render_overlay(name or latest.action, metadata, latest.phase or latest.message, latest.host_pid)
        elif overlay_window.isVisible():
            overlay_window.hide()

    def display_queue():
        queued = moves.snapshot()
        last, repeating = moves.repeat_status()
        repeat.setEnabled(latest.lock_available and last is not None)
        repeat.setChecked(repeating is not None)
        repeat.setText("循环上一招 · 开" if repeating else "循环上一招 · 关")
        repeat_name.setVisible(repeating is not None)
        repeat_name.setText((saved_name(repeating) or action_name(repeating)) if repeating else "")
        state_ready = not switching and latest.lock_available and len(queued) < QUEUE_LIMIT
        fight_state.setEnabled(state_ready and latest.fight_state_control)
        special_state.setVisible(shown_monster in (48, 114))
        special_state.setEnabled(state_ready and latest.expanded_actions)
        headings = [saved_name(action) or action_name(action) for action in queued]
        queue_text = f"待执行 {len(queued)}/{QUEUE_LIMIT}"
        if headings:
            queue_text += "   " + " → ".join(headings)
        move_list.setText(queue_text)
        set_action_buttons_ready(not switching and latest.lock_available and len(queued) < QUEUE_LIMIT)
        for header in group_headers.values():
            if header.property("waiting") != (not state_ready):
                header.setProperty("waiting", not state_ready)
                header.style().unpolish(header)
                header.style().polish(header)

    def toggle_repeat(enabled):
        moves.set_repeat(enabled)
        display_queue()

    repeat.clicked.connect(toggle_repeat)

    def refresh():
        nonlocal switching, latest, pending_target, shown_targets, shown_monster, shown_reactions
        nonlocal detail_group
        update = None
        try:
            while True:
                update = updates.get_nowait()
        except Empty:
            pass
        if update is not None:
            latest = update
            if pending_target is not None:
                if latest.selected != pending_target and pending_target in latest.targets:
                    return
                pending_target = None
            switching = False
            tabs.blockSignals(True)
            if latest.targets != shown_targets:
                shown_targets = latest.targets
                while tabs.count():
                    tabs.removeTab(0)
                labels = [monster_names.get(target[-1], f"em{target[-1]:03}") for target in shown_targets]
                seen = {}
                for target, name in zip(shown_targets, labels):
                    seen[name] = seen.get(name, 0) + 1
                    label = f"{name} {seen[name]}" if labels.count(name) > 1 else name
                    index = tabs.addTab(label)
                    tabs.setTabToolTip(index, f"em{target[-1]:03} · 槽位 {target[1] + 1}")
            if latest.selected in shown_targets:
                tabs.setCurrentIndex(shown_targets.index(latest.selected))
                selected_monster.setText(tabs.tabText(tabs.currentIndex()))
            else:
                selected_monster.setText("等待任务中的怪物")
            tabs.blockSignals(False)
            monster_id = latest.selected[-1] if latest.selected else None
            if monster_id != shown_monster or latest.reaction_numbers != shown_reactions:
                if monster_id != shown_monster:
                    detail_group = None
                    manager.hide()
                shown_monster = monster_id
                shown_reactions = latest.reaction_numbers
                populate(monster_id, shown_reactions)
            lock.setEnabled(latest.lock_available)
            lock.setChecked(latest.locked)
            lock.setText("禁止自主动作 · 开" if latest.locked else "禁止自主动作 · 关")
            for action, button in buttons.items():
                button.setEnabled(latest.expanded_actions or action[0] in (2, 3, 7))
            connection.setText(
                f"{latest.emulator} · {'已连接 4G' if latest.host_pid else '已检测到'}"
                if latest.emulator else "未连接模拟器"
            )
            status.setText(latest.message)
            disk = {
                "installed": "已安装",
                "missing": "未安装",
                "conflict": "已有其他 ExeFS 文件",
                "unknown": "无法识别 Mod 目录",
            }.get(latest.patch_disk, "等待 4G 连接")
            suffix = (" · 本局已加载" if latest.patch_loaded else " · 本局未加载") if latest.host_pid else ""
            patch_state.setText(disk + suffix)
            install_patch.setEnabled(latest.patch_disk == "missing" and not latest.patch_loaded)
            uninstall_patch.setEnabled(latest.patch_disk == "installed")
            if not latest.selected or latest.hunter_slot == 255:
                hunter = "—"
            elif latest.hunter_slot < 4:
                hunter = f"玩家 {latest.hunter_slot + 1}"
            else:
                hunter = f"槽位 {latest.hunter_slot}"
            target_label.setText(f"当前猎人目标 · {hunter}")
            target_menu.setCurrentIndex(latest.target_mode)
        target_menu.setEnabled(not switching and latest.target_control)
        display_current()
        display_queue()

    timer = QTimer(window)
    timer.timeout.connect(refresh)
    timer.start(100)
    Thread(target=watch, args=(actions, reactions, outgoing, moves, updates, done), daemon=True).start()
    window.show()
    app.lastWindowClosed.connect(app.quit)
    try:
        app.exec()
    finally:
        done.set()
        overlay_window.close()


def runtime_actions():
    if not (RESOURCE_DIRECTORY / "monster-actions.json").is_file():
        return monster_action_catalog()
    catalog = json.loads((RESOURCE_DIRECTORY / "monster-actions.json").read_text(encoding="utf-8"))
    return {int(key): [bytes.fromhex(action) for action in actions]
            for key, actions in catalog["actions"].items()}


def runtime_names():
    if not (RESOURCE_DIRECTORY / "monster-actions.json").is_file():
        return localized_monster_names() | MONSTER_DISPLAY_NAMES
    catalog = json.loads((RESOURCE_DIRECTORY / "monster-actions.json").read_text(encoding="utf-8"))
    return {int(key): name for key, name in catalog["names"].items()} | MONSTER_DISPLAY_NAMES


def runtime_reactions():
    path = RESOURCE_DIRECTORY / "monster-actions.json"
    if not path.is_file():
        path = RESOURCE_DIRECTORY / "build/remote-standalone/monster-actions.json"
    if not path.is_file():
        return {}
    catalog = json.loads(path.read_text(encoding="utf-8"))
    return {int(key): tuple(numbers) for key, numbers in catalog.get("reactions", {}).items()}


def diagnostics(actions, reactions):
    emulator, name, message = select_emulator(running_emulators(), rpc_owners(RPC_PORT))
    result = {"detected": name, "pid": emulator.pid if emulator else None, "message": message}
    if emulator is None:
        return result
    memory = Memory()
    try:
        memory.verify_game()
        state = asdict(Remote(memory, actions, emulator, reactions).snapshot())
        if state["staged"] is not None:
            state["staged"] = action_name(state["staged"])
        result.update(state, connected=True)
    except (ReadError, OSError) as error:
        result.update(connected=False, message=str(error))
    finally:
        memory.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check the loaded game without sending commands.")
    parser.add_argument("--diagnostics", type=Path, help="Write a read-only connection report.")
    args = parser.parse_args()
    actions = runtime_actions()
    reactions = runtime_reactions()
    if args.diagnostics:
        report = dict(diagnostics(actions, reactions), monster_count=len(actions),
                      action_count=sum(map(len, actions.values())),
                      reaction_dispatchers=len(reactions))
        args.diagnostics.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return
    if not args.check:
        show_ui(actions, runtime_names(), reactions)
        return
    memory = Memory()
    try:
        memory.verify_game()
        print(Remote(memory, actions, reactions=reactions).snapshot())
    except (OSError, ReadError) as error:
        parser.exit(1, f"{error}\n")
    finally:
        memory.close()


if __name__ == "__main__":
    main()
