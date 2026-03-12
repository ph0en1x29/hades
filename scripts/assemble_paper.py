#!/usr/bin/env python3
"""Assemble paper sections into a single reviewable Markdown draft."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).parent.parent
SECTIONS_DIR = ROOT / 'paper' / 'sections'
OUTPUT = ROOT / 'paper' / 'HADES_PAPER_DRAFT.md'

ORDER = [
    '00_abstract.md',
    '01_introduction.md',
    '02_background.md',
    '03_threat_model.md',
    '04_system_architecture.md',
    '05_methodology.md',
    '06_results.md',
    '07_discussion.md',
    '08_related_work.md',
    '09_references.md',
]


def main() -> None:
    parts = [
        '# Hades: Adversarial Manipulation of LLM-Based SOC Triage Systems Through Crafted Network Traffic',
        '',
        '> Working draft assembled automatically from `paper/sections/`.',
        '',
    ]

    for filename in ORDER:
        path = SECTIONS_DIR / filename
        if not path.exists():
            parts.append(f'\n<!-- Missing section: {filename} -->\n')
            continue
        parts.append(path.read_text().rstrip())
        parts.append('')
        parts.append('\n---\n')
        parts.append('')

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text('\n'.join(parts).rstrip() + '\n')
    print(f'Assembled draft: {OUTPUT}')


if __name__ == '__main__':
    main()
