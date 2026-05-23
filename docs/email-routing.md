# Identrail Email Routing

This document records the public mailbox roles used across Identrail websites, apps, docs, and operational configuration.

## Mailboxes

- `security@identrail.com`: vulnerability reports, responsible disclosure, security.txt, security policy, and private security reporting.
- `support@identrail.com`: account help, access issues, privacy requests, data deletion requests, terms questions, and user support.
- `contact@identrail.com`: general website contact, partnerships, enterprise inbound, and default lead-capture sender.
- `marketing@identrail.com`: marketing follow-up, product updates, campaign replies, and lead-capture notification routing.
- `founder@identrail.com`: founder inbox and private direct contact. Do not publish broadly on public surfaces by default.

## Public Surface Rules

- Do not route privacy, deletion, terms, or support requests to `security@identrail.com` unless the request is a security incident.
- Use `support@identrail.com` for user-facing account and policy help.
- Use `contact@identrail.com` for generic public contact links and lead sender configuration.
- Include `marketing@identrail.com` only where the message is clearly a marketing or lead follow-up workflow.
- Keep `founder@identrail.com` out of automated forms, footer links, and docs unless a founder-led contact path is intentionally added.

## Current Integration Points

- `web/public/security.txt`, `SECURITY.md`, `README.md`, and `/responsible-disclosure`: `security@identrail.com`.
- Website footer contact link: `contact@identrail.com`.
- Privacy and terms pages: `support@identrail.com`.
- GitHub issue support guidance: `support@identrail.com`.
- Lead capture docs and test configuration: `LEAD_NOTIFY_TO=contact@identrail.com,marketing@identrail.com` and `LEAD_EMAIL_FROM=Identrail <contact@identrail.com>`.
