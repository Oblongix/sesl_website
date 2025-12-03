# SESL Website

## Overview
Simple Expert System Language (SESL) is a deterministic, rule-based expert system focused on repeatable and explainable outputs. This static site explains the product, showcases usage patterns, and links to downloads and resources.

## Key Pages
- `index.html`: Home/hero, core features, how SESL works, video placeholder, download modal, dark-mode toggle.
- `product.html`: Product overview plus sections for usage (LLM + local), language structure examples, CLI online vs batch modes, linter, and dependency graphing.
- `solutions.html`, `customers.html`, `resources.html`, `pricing.html`, `about.html`: Additional marketing and documentation pages referenced from the navigation.
- `guides/CLI_User_Guide.html`, `guides/Language_User_Guide.html`: User guide placeholders linked from the Resources page.

## Running Locally
- No build step: open `index.html` in a browser or serve the folder with any static server.
- Styling is via Tailwind CDN; code highlighting on `product.html` uses Highlight.js CDN.
- Dark mode is toggled in-page and remembered via `localStorage`.

## Downloads & Forms
- The "Download SESL" modal posts to Formspree and redirects to the SESL GitHub releases URL (`_redirect` hidden field). Update the Formspree endpoint or redirect as needed.

## Assets
- Stored under `assets/` (logos, favicon, screenshots, and customer logos).
- Examples: `passport_example.sesl`, customer policy HTML files.

## Editing Tips
- Keep content ASCII and reuse the existing Tailwind/Highlight.js CDNs for consistency.
- Replace `VIDEO_ID_HERE` in `index.html` with the actual YouTube video ID when available.
- Navigation and footer links are duplicated across pages; update them consistently.
