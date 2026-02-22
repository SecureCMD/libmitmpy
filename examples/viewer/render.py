from rich.text import Text

MAX_DISPLAY_BYTES = 16 * 1024  # 16 KiB — truncate beyond this to keep the UI responsive


def hex_dump(data: bytes) -> str:
    COLS = 16  # bytes per row
    GROUP = 8  # bytes per space-separated group within a row
    lines = []
    for i in range(0, len(data), COLS):
        row = data[i : i + COLS]
        groups = []
        for g in range(0, COLS, GROUP):
            chunk = row[g : g + GROUP]
            groups.append(f"{' '.join(f'{b:02x}' for b in chunk):<{GROUP * 3 - 1}}")
        hex_part = "  ".join(groups)
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:08x}  {hex_part}  |{printable}|")
    return "\n".join(lines)


def render_hex(data: bytes) -> Text:
    display = data[:MAX_DISPLAY_BYTES]
    content = Text(hex_dump(display), style="green")
    if len(data) > MAX_DISPLAY_BYTES:
        content.append(
            f"\n\n… {len(data) - MAX_DISPLAY_BYTES} more bytes not shown",
            style="dim italic",
        )
    return content


def render_text(data: bytes) -> Text:
    """Decode as UTF-8, replacing undecodable bytes with \ufffd."""
    display = data[:MAX_DISPLAY_BYTES]
    content = Text(display.decode("utf-8", errors="replace"))
    if len(data) > MAX_DISPLAY_BYTES:
        content.append(
            f"\n\n… {len(data) - MAX_DISPLAY_BYTES} more bytes not shown",
            style="dim italic",
        )
    return content
