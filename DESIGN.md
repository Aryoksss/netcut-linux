# DESIGN.md, netcut-linux

Design direction for the dashboard. This is the soul; `antislop` is the filter applied
on top of it. Every choice below has a one-line reason (antislop R-31).

## Reading

**Reading this as:** an operator console for a home or small-office LAN, read by someone
who knows what an ARP table is, in an instrument-panel language (dense rows, tabular
figures, quiet surfaces), dial **ENERGY 1 / RHYTHM 2 / MOTION 1**.

- **ENERGY 1**: the screen is calm until something is actually wrong. No decoration
  competing with the data.
- **RHYTHM 2**: one dominant element (the host table), a compact status strip, and
  occasional full-width warning blocks. Not uniform, not busy.
- **MOTION 1**: hover, focus, and one row highlight. No loops, no entrance animations.

## Who opens it, and what they want

One sentence: *"Which device on my LAN is eating the link or behaving badly, and what do
I do about it?"*

Everything on the screen is either the answer to that question or evidence for it. A
number that is neither moves into the strip, into a row, or off the screen.

The screen is read at three speeds, and each one is served:

| Speed | What it needs | Where it lives |
|---|---|---|
| 5 s | Is anything wrong? | The answer line above the table, in words, with the data's age |
| 30 s | Which device? | The table, sorted by traffic, status rail on the rows that need action |
| minutes | Why, and what do I do? | Row actions, the nft rules dialog, the "how it works" details |

## Palette

Two surfaces, one accent, three semantic colours. Neutrals carry the layout; colour is
information.

### Dark (default)

| Token | Value | Job |
|---|---|---|
| `--bg` | `#0f1116` | canvas, lifted near-black so surfaces can layer above it |
| `--panel` | `#15181f` | the table and the strip |
| `--panel-2` | `#1b1f28` | sticky header, hover row, input wells |
| `--line` | `#262b36` | hairlines between rows and sections |
| `--fg` | `#e7ecf3` | primary text, 15.9:1 on canvas |
| `--fg2` | `#a9b3c1` | secondary text, 8.9:1 |
| `--dim` | `#7d8798` | labels and units, 5.2:1 |
| `--accent` | `#4d9fe0` | selection, focus, the one primary action, 6.6:1 |
| `--ok` | `#5cba7d` | capture running, 7.9:1 |
| `--warn` | `#d8a43f` | limited, degraded, 8.4:1 |
| `--bad` | `#e2706e` | blocked, failed, 6.1:1 |

### Light

`#f6f7f9` canvas, `#ffffff` panel, `#454e5c` secondary text, `#1f6fb2` accent. All text
tokens measured at 4.71:1 or better against every surface they sit on.

**Why blue for the accent:** selection and focus are blue by universal convention in this
category. The AI tell is the indigo-to-violet gradient, not blue itself; this accent is a
desaturated steel blue used in exactly three places.

**Why the palette is this small:** with two surfaces and one accent, the semantic colours
are the only saturated things on screen, so a red row genuinely means something.

## Typography

- **UI text**: the system sans stack. Body 13px, labels 11px, headings 15px, no display
  face. A tool borrowed from the desktop should look like it belongs there.
- **Identifiers**: monospace for IP and MAC only. They are compared character by
  character, so fixed width is a reading aid, not a costume.
- **Quantities**: body sans with `font-variant-numeric: tabular-nums`, right-aligned. A
  rate column must align down the digits, and mono for numbers makes a table look like a
  terminal cosplay.
- **Table headers**: 11px, sentence case, medium weight, `--dim`. Uppercase with wide
  tracking was removed: it is the generic "technical" costume and it hurts scanning.

## Density

- Rows 30px, header 32px, table footer 30px. Chosen for scanning, not for touch.
- Hairline separators, no zebra stripes: zebra fights the status rail and the hover row.
- Numbers right-aligned; the deciding column (traffic) is never off-screen at 1280px.
- The footer states the row count and the column sums, so the reader never adds by hand.

## States

- **Empty** (no hosts yet): says why and offers the one action, "Scan ARP".
- **Loading** (first paint): says what is loading.
- **Error** (scan failed, capture lost): says what failed and what to do next. A zero is
  never used to mean "unknown".
- **Stale**: the answer line carries the age of the data at all times.
- **Fallback mode**: a full-width block, not a badge alone, because the consequence is
  that Block and Limit do nothing.

## Motion

Hover and focus only, 120ms. One exception: the bulk bar slides in when a selection
starts, because it changes what the screen can do.

## Identity motif

Three things repeat and make the screen belong to this tool:

1. **The answer line**: a single sentence above the table that states the situation in
   words, in the same position on every load.
2. **The status rail**: a 2px left edge on a row that is blocked (red) or limited (amber).
   It carries state, not decoration, and it is the only place colour touches a row.
3. **Tabular right-aligned quantities**: every number on the screen aligns with every
   other number in its column.

## What was removed, and why

| Removed | Reason |
|---|---|
| Five equal KPI cards | presented five unequal facts as equal citizens, and buried the table |
| Uptime badge in the toolbar | a number nobody acts on, sitting where a status belongs |
| Uppercase headers with 0.6px tracking | generic technical costume, slower to scan |
| Glowing status dot | borrowed liveness vocabulary as decoration; the dot now marks a real state with no glow |
| Pill-shaped filter chips | radius as decoration; chips are now 4px controls that read as controls |
| 10px radius and a shadow on every surface | elevation that is everywhere communicates nothing |
| Card sub-labels full of em dashes | empty chrome where the eye expects information |
