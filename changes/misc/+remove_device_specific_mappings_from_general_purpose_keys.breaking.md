Removed device specific mappings from general purpose keys

FK13 - FK18 where mapped to XF86Tools and XF86Launch5 - XF86Launch9. Following
the git log, this was done for just hand full of specific devices that had it
labled like this. This patch mapps them to the general purpose F13 - F18 symbols
for the user to self define what these should be doing.

It also fixes odd behavor when trying to bind an electron shortcut to F13 - F18.
