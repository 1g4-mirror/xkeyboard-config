Made <ZEHA> behave like <FK24>

On Linux Kernel before v6.17, the scancode for F24 was bound to the otherwise
unused <ZEHA> keycode. v6.17 fixed this. To have a consistent behaviour across
kernel versions, make both <ZEHA> and <FK24> behave the same.
