# Vendored assets

Served from `/static`, committed to the tree, **never fetched at runtime**. There are zero
external origins anywhere in `quarry/web/` and `tests/test_design_tokens.py` asserts it stays
that way. A font or script fetched from a CDN would be egress that the egress ledger is
structurally incapable of recording, because the browser would issue it, not `quarry`.

A tool that stores every quarantined scanner config as prefix + SHA-256 should not serve
unattributed third-party bytes. So:

| file | version | bytes | sha256 | upstream |
|---|---|---|---|---|
| `htmx.min.js` | 2.0.4 | 50917 | `e209dda5c8235479f3166defc7750e1dbcd5a5c1808b7792fc2e6733768fb447` | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js |
| `alpine.min.js` | 3.14.8 | 44758 | `b600e363d99d95444db54acbfb2deffec9ae792aa99a09229bcda078e5b55643` | https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js |
| `inter-latin-wght-normal.woff2` | 5.2.5 | 48444 | `f052ee44c3728dfd23aba8a4567150bc314d23903026fbb6ad089422c2df56af` | https://cdn.jsdelivr.net/npm/@fontsource-variable/inter@5.2.5/files/inter-latin-wght-normal.woff2 |

`tests/test_packaging.py::test_vendored_assets_match_recorded_hashes` recomputes every row and
fails if a file drifts from this table. To upgrade: replace the file, update the row, run the
test.

## Fonts

Inter, for consistency with the RogoLabs brand. One file: the Latin subset of the variable
font from `@fontsource-variable/inter` 5.2.5, covering the 400, 500 and 600 weights the
product uses. It is vendored so the browser makes no request to a font host. Inter is under
the SIL Open Font License 1.1; the text is in `INTER-LICENSE.txt` beside it. The fontsource
package's own LICENSE file names "Google Inc." in its header line; the copyright line in
`INTER-LICENSE.txt` is the upstream Inter project's. Mono text uses the system
`ui-monospace` stack and no webfont.
