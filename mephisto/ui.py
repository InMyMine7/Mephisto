"""Rendering primitives for the Mephisto terminal UI.

Everything that draws to the terminal lives here so the engine stays a plain
library and the look of the tool changes in one place.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

from colorama import Fore, Style

RESET = Style.RESET_ALL

ACCENT = Fore.GREEN
MUTED = Fore.WHITE
WARN = Fore.YELLOW
DANGER = Fore.RED
INFO = Fore.CYAN
FAINT = Style.DIM

STATUS_COLOR = {
    "VULN": Fore.GREEN,
    "NO": Style.DIM + Fore.WHITE,
    "ERROR": Fore.YELLOW,
    "TIMEOUT": Fore.MAGENTA,
}

STATUS_LABEL = {
    "VULN": "VULN",
    "NO": "clean",
    "ERROR": "error",
    "TIMEOUT": "timeout",
}


def _prepare_console() -> None:
    """Switch the Windows console to UTF-8 so box drawing renders."""
    if os.name != "nt" or os.environ.get("MEPHISTO_ASCII"):
        return
    try:
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        ctypes.windll.kernel32.SetConsoleCP(65001)
    except Exception:
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _unicode_supported() -> bool:
    if os.environ.get("MEPHISTO_ASCII"):
        return False
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
    return "utf" in encoding


_prepare_console()


class _Glyphs:
    def __init__(self, unicode: bool):
        if unicode:
            self.tl, self.tr, self.bl, self.br = "\u250c", "\u2510", "\u2514", "\u2518"
            self.v, self.lt, self.rt = "\u2502", "\u251c", "\u2524"
            self.tt, self.bt, self.cross = "\u252c", "\u2534", "\u253c"
            self.h = "\u2500"
            self.bullet, self.arrow, self.ellipsis = "\u00b7", "\u2192", "\u2026"
            self.bar_full, self.bar_empty = "\u2588", "\u2591"
        else:
            self.tl = self.tr = self.bl = self.br = "+"
            self.v = self.lt = self.rt = self.tt = self.bt = self.cross = "|"
            self.h = "-"
            self.bullet, self.arrow, self.ellipsis = "*", "->", "~"
            self.bar_full, self.bar_empty = "#", "-"


GLYPH = _Glyphs(_unicode_supported())

_VERBOSE = False


def set_verbose(enabled: bool) -> None:
    """Module chatter is hidden by default so progress lines stay readable."""
    global _VERBOSE
    _VERBOSE = bool(enabled)


def is_verbose() -> bool:
    return _VERBOSE


def term_width(limit: int = 96) -> int:
    """Usable drawing width, clamped so panels stay readable on wide screens."""
    columns = shutil.get_terminal_size((80, 24)).columns
    return max(60, min(columns - 1, limit))


def paint(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if color else str(text)


def truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + GLYPH.ellipsis if width > 1 else GLYPH.ellipsis


def _is_styled(value) -> bool:
    return isinstance(value, (tuple, list))


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    """Visible width helper shared by callers and tests."""
    return _ANSI.sub("", str(text))


def _cell_raw(value) -> str:
    """Visible text of a cell; ANSI codes never count toward column width."""
    if _is_styled(value):
        return str(value[0])
    return _strip_ansi(value)


def _cell_draw(value, width: int, align: str) -> str:
    raw = truncate(_cell_raw(value), width)
    drawn = paint(raw, value[1]) if _is_styled(value) else raw
    filler = " " * (width - len(raw))
    return f" {drawn}{filler} " if align == "left" else f" {filler}{drawn} "


# --------------------------------------------------------------------------- #
# Building blocks
# --------------------------------------------------------------------------- #


def rule(label: str = "", width: int | None = None, color: str = ACCENT) -> None:
    width = width or term_width()
    if not label:
        print(paint(GLYPH.h * width, FAINT))
        return
    head = f"{GLYPH.h}{GLYPH.h} {label.upper()} "
    print(paint(head, color) + paint(GLYPH.h * max(0, width - len(head)), FAINT))


def table(headers, rows, aligns=None, indent: int = 2, width: int | None = None) -> None:
    """Render a bordered table; cells may be plain strings or (text, colour)."""
    if not rows:
        return

    width = width or term_width()
    columns = len(headers)
    aligns = aligns or ["left"] * columns

    widths = [len(str(header)) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(_cell_raw(cell)))

    chrome = 3 * columns + 1 + indent
    while sum(widths) + chrome > width and max(widths) > 8:
        widths[widths.index(max(widths))] -= 1

    def border(left, middle, right):
        return (
            " " * indent
            + paint(left, FAINT)
            + paint(middle, FAINT).join(paint(GLYPH.h * (w + 2), FAINT) for w in widths)
            + paint(right, FAINT)
        )

    def render(cells):
        parts = [_cell_draw(cell, widths[i], aligns[i]) for i, cell in enumerate(cells)]
        return " " * indent + paint(GLYPH.v, FAINT) + paint(GLYPH.v, FAINT).join(parts) + paint(GLYPH.v, FAINT)

    print(border(GLYPH.tl, GLYPH.tt, GLYPH.tr))
    print(render([(str(header), Style.BRIGHT + Fore.WHITE) for header in headers]))
    print(border(GLYPH.lt, GLYPH.cross, GLYPH.rt))
    for row in rows:
        print(render(list(row)))
    print(border(GLYPH.bl, GLYPH.bt, GLYPH.br))


def badge(status: str) -> tuple:
    return (STATUS_LABEL.get(status, status), STATUS_COLOR.get(status, MUTED))


def key_value(rows, indent: int = 2) -> None:
    """Aligned ``key . value`` block without a border."""
    key_width = max((len(str(key)) for key, _ in rows), default=0)
    for key, value in rows:
        print(
            f"{' ' * indent}{paint(str(key).ljust(key_width), FAINT)} "
            f"{paint(GLYPH.bullet, FAINT)} {value}"
        )


def banner(version: str, totals: dict) -> None:
    art = r"""
 /$$      /$$                     /$$       /$$             /$$
| $$$    /$$$                    | $$      |__/            | $$
| $$$$  /$$$$  /$$$$$$   /$$$$$$ | $$$$$$$  /$$  /$$$$$$$ /$$$$$$    /$$$$$$
| $$ $$/$$ $$ /$$__  $$ /$$__  $$| $$__  $$| $$ /$$_____/|_  $$_/   /$$__  $$
| $$  $$$| $$| $$$$$$$$| $$  \ $$| $$  \ $$| $$|  $$$$$$   | $$    | $$  \ $$
| $$\  $ | $$| $$_____/| $$  | $$| $$  | $$| $$ \____  $$  | $$ /$$| $$  | $$
| $$ \/  | $$|  $$$$$$$| $$$$$$$/| $$  | $$| $$ /$$$$$$$/  |  $$$$/|  $$$$$$/
|__/     |__/ \_______/| $$____/ |__/  |__/|__/|_______/    \___/   \______/
                       | $$
                       |__/
"""
    for line in art.strip("\n").splitlines():
        print(paint(line, ACCENT))

    print()
    print(
        f"  {paint('WordPress Auto Exploit Framework', Style.BRIGHT + Fore.WHITE)}"
        f"   {paint('v' + version, ACCENT)}"
    )
    print(
        f"  {paint(str(totals.get('exploits', 0)), Fore.WHITE)} exploits"
        f"  {paint(GLYPH.bullet, FAINT)}  "
        f"{paint(str(totals.get('payloads', '0/0')), Fore.WHITE)} payloads"
        f"  {paint(GLYPH.bullet, FAINT)}  "
        f"{paint('authorized testing only', WARN)}"
    )
    notice_text = totals.get("notice", "")
    if notice_text:
        print(f"  {paint('!', WARN)} {paint(notice_text, WARN)}")
    rule(color=ACCENT)


def notice(text: str, kind: str = "info") -> None:
    colour = {"info": INFO, "ok": ACCENT, "warn": WARN, "error": DANGER}.get(kind, INFO)
    mark = {"info": GLYPH.bullet, "ok": "+", "warn": "!", "error": "x"}.get(kind, GLYPH.bullet)
    print(f"  {paint(mark, colour)} {text}")


def prompt(message: str, default: str = "") -> str:
    suffix = f" {paint('[' + default + ']', FAINT)}" if default else ""
    try:
        return input(f"  {paint(GLYPH.arrow, ACCENT)} {message}{suffix} ").strip()
    except EOFError:
        return ""


def pause(message: str = "Press Enter to continue") -> None:
    try:
        input(f"\n  {paint(GLYPH.bullet, FAINT)} {paint(message, FAINT)} ")
    except EOFError:
        pass


def metric_bar(value: int, total: int, width: int = 12, color: str | None = None) -> str:
    if total <= 0:
        return paint(GLYPH.bar_empty * width, FAINT)
    filled = int(round(width * value / total))
    return paint(GLYPH.bar_full * filled, color or ACCENT) + paint(GLYPH.bar_empty * (width - filled), FAINT)
