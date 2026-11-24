# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

project = Path(SPECPATH)
project_link = project / "github-project.txt"
datas = [(str(project / "monster-actions.json"), ".")]
if project_link.is_file():
    datas.append((str(project_link), "."))
a = Analysis(
    [str(project / "mh4g_remote.py")],
    pathex=[str(project)],
    datas=datas,
    excludes=["keystone", "unicorn"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="MH4GRemote", console=False)
