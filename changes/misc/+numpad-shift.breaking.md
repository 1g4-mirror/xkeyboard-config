numpad  key types: Changed `FOUR_LEVEL_KEYPAD` and `FOUR_LEVEL_MIXED_KEYPAD`
so that they are identical and enable to use `Shift` in keyboard shortcuts
with *both* arrows/edition keys and numbers:

- `Shift` maps to level 1, usually corresponding to numpad `KP_`
  arrows/editing keysyms variants);
- `Shift` is preserved.
- No “`Shift` cancels `NumLock`” behavior.

All numpad key types have now the same consistent behavior with `Shift`
and `NumLock`.
