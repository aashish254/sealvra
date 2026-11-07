# The Tk half of the width proof. design/qa/probe-widths.cjs measures the
# mockups in Chromium; this measures the real control panel: it drives the
# window through every breakpoint and reads tree.xview() per screen, so
# "FITS" means that tree is not showing a horizontal scrollbar - the symptom
# of a column floor-sum wider than the box (table-layout: fixed makes the
# declared widths a minimum, and Tk behaves the same way).
# run: .venv/bin/python design/qa/probe-tk-widths.py
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from sealvra import gui
import test_w11_gui as T

win = gui.SealvraWindow(source=T.FakeSource())
root = win.root
worst = []
try:
    for w in (1440, 1360, 1329, 1328, 1200, 1100, 1074, 1073, 900, 780, 760):
        root.geometry(f"{w}x820+60+40")
        root.update_idletasks(); root.update()
        parts = []
        for name in ("sessions", "keys", "activity"):
            win.show_view(name)
            root.update_idletasks(); root.update()
            spec = gui.TABLE_SPECS[name]
            tree = win.views[name]["tree"]
            cols = list(win._apply_columns(tree, name))
            total = sum(spec["widths"][c] for c in cols)
            lo, hi = tree.xview()
            fits = hi >= 0.999
            parts.append(f"{name[:4]} {total:>4} {'FITS' if fits else 'SCROLL'}")
            if not fits:
                worst.append((w, name, total, round(tree.winfo_width(), 1), round(1 - hi, 4)))
        print(f"{w:>5}px  " + " | ".join(parts))
finally:
    # Each breakpoint is drawn on the owner's desktop, so a SCROLL verdict or
    # a crash must not leave the measured window mapped behind it.
    root.destroy()
print()
for x in worst:
    print("SHORT", x)
