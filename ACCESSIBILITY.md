# Accessibility

repo-checks is a developer tool library and CI action repository, with no public
end-user web or native app UI. Its new browser check is tested against synthetic
pages only. It is not an accessibility auditor or compliance certificate.

Our [engineering standard](docs/ACCESSIBILITY_STANDARD.md) applies to code,
documentation and consumer UIs. The shared axe action checks selected WCAG A/AA
rules in Chromium and WebKit, desktop and mobile widths. Manual evaluation and
native device testing remain separate requirements. No whole-product manual
or SI 5568 conformance audit has been completed for this repository.

Report an accessibility problem through this repository's GitHub Issues.
Include the affected tool or document, steps and assistive technology if useful;
do not post personal data or credentials. Known limitations and rollout gaps are
tracked in #49 and consumer-specific issues. Last updated: 2026-11-11.
