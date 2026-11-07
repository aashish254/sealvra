# The Tk half of the touch-target proof. design/qa/audit.cjs fails a mockup
# screen on any visible control shorter than 28px; this asks the same question
# of the real control panel, because ttk decides a widget's height from font
# plus padding and a style that forgets the padding ships a 22px checkbox.
# run: .venv/bin/python design/qa/probe-tk-targets.py
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests"))
from sealvra import gui
import test_w11_gui as T

FLOOR = 28
CLASSES = ("TCheckbutton", "Checkbutton", "TRadiobutton", "Radiobutton",
           "TButton", "Button", "TEntry", "Entry", "Treeview")

win = gui.SealvraWindow(source=T.FakeSource())
root = win.root


def walk(w, out):
    for c in w.winfo_children():
        if c.winfo_class() in CLASSES:
            out.append(c)
        walk(c, out)


worst = []
try:
    for view in ("sessions", "keys", "activity", "service", "log"):
        win.show_view(view)
        for w in (1440, 1328, 1073, 900, 760):
            root.geometry(f"{w}x820+60+40")
            root.update_idletasks(); root.update()
            found = []
            walk(root, found)
            for b in found:
                if not b.winfo_ismapped():
                    continue
                h = b.winfo_height()
                if h < FLOOR:
                    worst.append((view, w, b.winfo_class(),
                                  str(b.cget("text"))[:28], h))
            print(f"{view:>9} {w:>5}px  {len([b for b in found if b.winfo_ismapped()])} mapped controls measured")
finally:
    # The measured window is a real window on the owner's desktop; an
    # exception or a failing verdict must not leave it mapped.
    root.destroy()

print()
if worst:
    for x in sorted(set(worst)):
        print(f"UNDER {x[0]} at {x[1]}px: {x[2]} {x[3]!r} is {x[4]}px (floor {FLOOR})")
    sys.exit(1)
print(f"PASS: every mapped control is at least {FLOOR}px tall")
