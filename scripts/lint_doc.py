#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lint_doc.py - 技术文档机械检查

用法:
    python lint_doc.py <文件> [<文件> ...]

检查项:
    E1 行尾注释
    E2 && / ; / || 串联多步
    E3 正文中裸露的 ASCII 占位符、xxx、your-host
    E4 命令块缺 # 目的 / # 预期；变更类命令缺 # 幂等
    E5 破坏性命令缺 # 危险
    E6 数字 + 以上/以下/以内
    W1 禁用词、程度词、黑话、模糊时间
    W2 数字与单位之间缺空格
    W3 正文句子超过 40 个汉字

约定:
    - 只对 bash/sh/powershell 等命令代码块检查命令格式；text/yaml 等块跳过。
    - 引号内的 # 与 && 不算注释或串联；URL 片段（api#section）不算注释。
    - for (...) 里的分号不算串联。
    - frontmatter（首个 --- 到下一个 ---）是元数据，跳过全部检查。
    - 表格行跳过正文检查（替换表、对照表里有意的反例）。
    - 规则里声明禁用词的行（"【必须】不用…"）跳过 W1。
    - 行级忽略：# lint:ignore E1,E2 放在命令行或块内注释行。
    - 全局开关：<!-- lint:off --> 与 <!-- lint:on --> 之间跳过。
    - 退出码: 有 E 级问题返回 1，否则 0；W 级只提示。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BT = chr(96)

CMD_LANGS = {"bash", "sh", "shell", "zsh", "powershell", "ps1", "cmd", "bat"}
RULE_HEAD = re.compile(r"^\s*-\s*【(必须|建议)】(不用|不写|禁用)")

BANNED = [
    (re.compile(r"(进行|加以|作出|予以)[\u4e00-\u9fff]"), "不用 进行/加以/作出/予以 + 动词"),
    (re.compile(r"(很|非常|大量|尽快|及时)[\u4e00-\u9fff]"), "无数值的程度词，写数值或范围"),
    (re.compile(r"(赋能|抓手|闭环|拉通|沉淀|痛点|对标)"), "黑话"),
    (re.compile(r"(明天|近期|稍后|目前|现在|最新|即将)"), "模糊时间或时效，写日期或版本号"),
]
NUM_RANGE = re.compile(r"\d+\s*(以上|以下|以内)")
NUM_UNIT = re.compile(r"\d(?=(个|台|次|秒|分钟|小时|天|周|个月|年|MB|GB|KB|TB|ms|核|条|行|页))")
DESTRUCTIVE = re.compile(
    r"(rm\s+-[rf]{1,2}|Remove-Item[^\n]*-Recurse|DROP\s+(TABLE|DATABASE)|mkfs\.|"
    r"format\s+[A-Za-z]:|shutdown\s|reboot\b|systemctl\s+(stop|disable)\s|"
    r"iptables\s+-F|net\s+user\s+\S+\s+\*|Set-Content\s+[^\n]*(sshd_config|\.conf)|"
    r"truncate\s+-s\s+0)"
)
STATE = re.compile(
    r"(systemctl\s+(restart|start|stop|reload|enable|disable)|service\s+\S+\s+(restart|start|stop)|"
    r"\brm\s|\bmv\s|\bcp\s|sed\s+-i|\btee\s|chmod\s|chown\s|apt(-get)?\s+(install|remove)|"
    r"yum\s|pip\s+install|docker\s+(run|rm|stop)|net\s+user|Set-Content|Add-Content|"
    r"Remove-Item|New-Item|Restart-Service|Start-Service|Stop-Service|Set-Service|"
    r"usermod|useradd|iptables|firewall-cmd)"
)
TAG_LIKE = re.compile(r"<[A-Za-z][A-Za-z0-9_.-]*>")
INLINE_CODE = re.compile(BT + "[^" + BT + "]*" + BT)
BAD_PLACEHOLDER = re.compile(r"(?<![A-Za-z0-9_-])(xxx|your-host)(?![A-Za-z0-9_-])")
FENCE = re.compile(r"^\s*" + BT + "{3}\s*([A-Za-z0-9_+.-]*)")
LINT_OFF = re.compile(r"<!--\s*lint:off\s*-->")
LINT_ON = re.compile(r"<!--\s*lint:on\s*-->")
IGNORE = re.compile(r"#\s*lint:ignore\s*([A-Za-z0-9, ]*)")
HEREDOC = re.compile(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?")


def strip_quoted(text):
    """把单/双引号内的字符替换成空格，用于注释与串联判断。"""
    out = []
    quote = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote is not None:
            if ch == "\\" and i + 1 < len(text):
                out.append(" ")
                out.append(" ")
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(" ")
        else:
            if ch in ("'", '"'):
                quote = ch
                out.append(" ")
            else:
                out.append(ch)
        i += 1
    return "".join(out)


def ignore_codes(text):
    m = IGNORE.search(text)
    if not m:
        return set()
    return {c.upper() for c in re.split(r"[,\s]+", m.group(1)) if c}


def has_trailing_comment(text):
    clean = strip_quoted(text)
    pos = clean.find("#")
    if pos <= 0:
        return False
    return clean[pos - 1] in " \t"


def flush_block(block, emit, lang):
    if lang not in CMD_LANGS or not block:
        return
    start = block[0][0]
    cmds = [(n, t) for n, t in block if not t.lstrip().startswith("#")]
    if not any(t.strip() for _, t in cmds):
        return
    joined = "\n".join(t for _, t in cmds)
    block_ignores = set()
    for _, t in block:
        block_ignores |= ignore_codes(t)
    has_purpose = any("# 目的" in t for _, t in block)
    has_expected = any("# 预期" in t for _, t in block)
    has_idem = any("# 幂等" in t for _, t in block)
    has_danger = any("# 危险" in t for _, t in block)
    if not has_purpose and "E4" not in block_ignores:
        emit(start, "E", "E4", "命令块缺少 # 目的：注释")
    if not has_expected and "E4" not in block_ignores:
        emit(start, "E", "E4", "命令块缺少 # 预期：判据")
    if STATE.search(joined) and not has_idem and "E4" not in block_ignores:
        emit(start, "E", "E4", "变更类命令缺少 # 幂等：标注")
    if DESTRUCTIVE.search(joined) and not has_danger and "E5" not in block_ignores:
        emit(start, "E", "E5", "破坏性命令缺少 # 危险：标注（影响范围 + 是否可逆）")
    for n, t in cmds:
        ign = ignore_codes(t)
        clean = strip_quoted(t)
        if "E2" not in ign:
            if "&&" in clean or "||" in clean:
                emit(n, "E", "E2", "用 && / ; / || 串联了多步，拆成命令块或脚本")
            elif re.search(r"(?<!\\);", clean) and not re.search(r"\bfor\s*\(", clean):
                emit(n, "E", "E2", "用 && / ; / || 串联了多步，拆成命令块或脚本")
        if "E1" not in ign and has_trailing_comment(t):
            emit(n, "E", "E1", "行尾注释会随命令被复制，移到命令上方")


def lint_text(text):
    findings = []
    lines = text.splitlines()

    def emit(line, level, rule, msg):
        findings.append((line, level, rule, msg))

    in_fence = False
    lang = ""
    lint_on = True
    in_frontmatter = False
    block = []
    heredoc = None

    for idx, raw in enumerate(lines, 1):
        if idx == 1 and raw.strip() == "---":
            in_frontmatter = True
            continue
        if in_frontmatter:
            if raw.strip() == "---":
                in_frontmatter = False
            continue
        if LINT_OFF.search(raw):
            lint_on = False
            continue
        if LINT_ON.search(raw):
            lint_on = True
            continue
        if not lint_on:
            continue
        fence = FENCE.match(raw)
        if fence:
            if in_fence:
                flush_block(block, emit, lang)
                block = []
                in_fence = False
                lang = ""
            else:
                in_fence = True
                lang = fence.group(1).lower()
            continue
        if in_fence:
            if heredoc:
                if raw.strip() == heredoc:
                    heredoc = None
                continue
            m = HEREDOC.search(raw)
            if m:
                heredoc = m.group(1)
            if not raw.strip():
                flush_block(block, emit, lang)
                block = []
                continue
            block.append((idx, raw))
            continue

        stripped = raw.lstrip()
        if stripped.startswith("|"):
            continue

        bare = INLINE_CODE.sub("", raw)
        for m in TAG_LIKE.finditer(bare):
            emit(idx, "E", "E3", "占位符 " + m.group(0) + " 在正文中必须放进反引号")
        if BAD_PLACEHOLDER.search(bare):
            emit(idx, "E", "E3", "禁用占位符 xxx / your-host，改用尖括号命名并注明取值")
        if NUM_RANGE.search(bare):
            emit(idx, "E", "E6", "数字 + 以上/以下/以内，改用 大于/不小于/不超过")
        if not RULE_HEAD.match(stripped):
            for rx, msg in BANNED:
                if rx.search(bare):
                    emit(idx, "W", "W1", msg)
                    break
        for m in NUM_UNIT.finditer(bare):
            emit(idx, "W", "W2", "数字与单位之间加空格：" + bare[max(0, m.start() - 2):m.end() + 2].strip())
        if not stripped.startswith(("#", ">", "-", "*")) and not re.match(r"^\d+\.", stripped):
            for sent in re.split(r"[。！？!?]", raw):
                cjk = len(re.findall(r"[\u4e00-\u9fff]", sent))
                if cjk > 40:
                    emit(idx, "W", "W3", "句子 " + str(cjk) + " 个汉字，超过 40，考虑拆分")
                    break

    if in_fence:
        flush_block(block, emit, lang)
    return findings


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    total = 0
    errors = 0
    for p in argv[1:]:
        path = Path(p)
        if not path.is_file():
            print(p + ": 不是文件，跳过")
            continue
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        findings = lint_text(text)
        findings.sort(key=lambda x: (x[0], x[2]))
        shown = str(path).replace("\\", "/")
        for line, level, rule, msg in findings:
            print(shown + ":" + str(line) + ": [" + level + "] " + rule + " " + msg)
        e = sum(1 for f in findings if f[1] == "E")
        errors += e
        total += len(findings)
        print(path.name + ": " + str(len(findings)) + " 条（E " + str(e) + " / W " + str(len(findings) - e) + "）")
    print("合计 " + str(total) + " 条，E 级 " + str(errors) + " 条")
    return 1 if errors else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sys.exit(main(sys.argv))
