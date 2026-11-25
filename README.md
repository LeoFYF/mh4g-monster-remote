# MH4G Monster Remote

作者：花露水企鹅。本软件由 AI 协助开发。

《怪物猎人 4G》1.2 的 Windows 怪物遥控器。通过 Citra 或 Azahar 的本机脚本 RPC 读取游戏状态。动作控制使用随附的 1.2 IPS 补丁。

- 在任务中切换怪物，查看当前动作、猎人目标和已识别的状态。
- 手动出招、存招、循环上一招，也可切换怪物自主行动。
- 每排显示三个动作组。左键执行默认代码，右键打开代码池管理。
- 支持已识别的状态切换、A 类受击反应和猎人目标选择。实际招式受怪物、状态和游戏路径影响。

## 参与招式图鉴

欢迎在仓库的 Issues 里提交招式命名、分类和同招异码的观察。先从[投稿说明](CONTRIBUTING.md)开始。

## 安装和运行

1. 使用 Windows、Python 3.11 或更新版本，以及提供脚本 RPC 的模拟器构建。遥控器连接本机 UDP 端口 `45987`。本项目实测使用过 Citra 7920a7d 的 RPC。
2. 启动 4G 1.2 并打开遥控器，在右上角选择「菜单 → 通用补丁」。这里显示磁盘安装状态和本局加载状态，也可安装或卸载。改动后完全退出并重新打开游戏。其他补丁会被保留。若模拟器使用自定义目录，可通过「打开 Mod 目录」手动放入 [代码补丁](patch/000400000011D700/exefs/code.ips)，相对路径为 `exefs/code.ips`。
3. 安装依赖后运行遥控器。

```powershell
python -m pip install -r requirements.txt
python mh4g_remote.py
```

默认目录使用怪物编号、动作编号和作者核对的变种名称。右键动作代码可命名并归组。自定义设置保存在程序目录的 `mh4g_remote_names.ini`。

## 构建 Windows 程序

```powershell
python -m pip install pyinstaller
python -m PyInstaller --noconfirm MH4GRemote.spec
```

程序生成在 `dist/MH4GRemote.exe`。命令 `python mh4g_remote.py --diagnostics report.json` 可生成只读连接报告。

若要重建补丁或目录，请自行转储对应版本的代码及资源到 `mh4g-unpacked/`。补丁构建器为 `build_em114_lock.py`，目录构建器为 `build_monster_reactions.py`，分别依赖 Keystone 和 Unicorn。默认发布包含数字动作目录和增量补丁，不含游戏本体、更新文件、转储、存档或个人设置。
