import { describe, expect, it } from 'vitest';
import { siteLinks } from '../siteConfig';
import { DOC_ENTRIES } from './resources';

const repoBase = 'https://github.com/identrail/identrail/';

function assertNoMainBranchLink(link: string) {
  if (!link.startsWith(repoBase)) {
    return;
  }

  expect(link).not.toContain('/blob/main/');
  expect(link).not.toContain('/tree/main/');
}

describe('repo link branch contract', () => {
  it('does not hardcode non-existent main branch links in site config', () => {
    for (const value of Object.values(siteLinks)) {
      if (typeof value !== 'string') {
        continue;
      }
      assertNoMainBranchLink(value);
    }
  });

  it('does not hardcode non-existent main branch links in doc entries', () => {
    for (const entry of DOC_ENTRIES) {
      assertNoMainBranchLink(entry.href);
    }
  });
});
