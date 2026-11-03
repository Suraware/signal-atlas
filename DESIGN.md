---
name: Signal Atlas
version: alpha
description: An evidence-first local security research workbench
colors:
  canvas: "#f4f6f9"
  surface: "#ffffff"
  navigation: "#17283e"
  text: "#17283e"
  muted: "#526276"
  border: "#d9e1ea"
  primary: "#235cc2"
  accent: "#167364"
typography:
  body:
    fontFamily: '"IBM Plex Sans", "Segoe UI", system-ui, sans-serif'
    fontSize: 16px
    lineHeight: 1.5
  heading:
    fontSize: 30px
    fontWeight: 650
    lineHeight: 1.2
spacing:
  unit: 4px
  small: 8px
  medium: 16px
  large: 24px
  page: 28px
rounded:
  control: 6px
  panel: 10px
components:
  button:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.control}"
---

# Signal Atlas design system

## Overview
An evidence-first security research workbench. Information density is intentional; the distinction between verified exploitation, scores, and unverified research is always visible in words.

## Colors
- Canvas: `#f4f6f9`
- Surface: `#ffffff`
- Navigation: `#17283e`
- Primary text: `#17283e`
- Secondary text: `#526276`
- Border: `#d9e1ea`
- Primary action: `#235cc2` (white text)
- Accent: `#167364` (white text)
- Critical: `#ae2539` on `#fff0f1`
- High: `#a04b0e` on `#fff4e7`
- Medium: `#735b04` on `#fff9db`
- Low: `#235cc2` on `#eef4ff`

## Typography
- Interface: locally installed `"IBM Plex Sans", "Segoe UI", system-ui, sans-serif`; no remote font requests.
- Identifiers/code: `"IBM Plex Mono", "Cascadia Code", ui-monospace, monospace`.
- Base: 16px, body line height 1.5. Heading: 30px/1.2, weight 650. Captions: 13–14px, never used for primary instructions.
- Sentence case; monospace only for identifiers, hashes, and code.

## Layout
- Desktop: 224px dark navigation; remaining light workspace with a 64px utility header and 28px padding.
- Content grid: lead research table/summary taking two thirds; evidence/source context taking one third.
- 4px spacing base; primary gaps 16/24/32px. Corners 6px for controls, 10px for panels, pill only for status badges.
- Under 900px: navigation becomes a compact top row and grids stack. At 390px: readable full-width controls; only data tables may scroll within labeled regions.
- Do not fill the dashboard with identical statistic cards. Use a clear page title, one compact metrics strip, and an evidence-led main panel.

## Elevation & Depth
White panels use quiet borders rather than decorative gradient washes. Only menus, confirmations, and transient feedback have a small functional shadow.

## Shapes
6px controls and 10px panels; status badges may be pills. A relationship node is not interchangeable with a statistic card.

## Components
- Real loading, empty, failure, and cached states. Never fake source health, score values, or timestamps.
- Prefer inline detail workspaces over custom modal traps. Native dialogs are allowed with Escape and focus restoration.
- Visible text on primary actions. Decorative SVG icons have aria-hidden; graph has a text relationship list.
- Focus outlines 3px blue; 44px control targets; reduced-motion preference removes animations.
- Notes are plain Markdown text, not executable HTML. Source links open only validated HTTP(S) URLs with rel=noopener noreferrer.

## Do's and Don'ts
- Use labeled status badges and source timestamps, not color alone.
- Use semantic tables and headings. Give the graph a readable relationship list.
- Keep body text readable and user actions at least 44px high.
- No invented records, fake live activity, remote assets, or unverified malware verdicts.
