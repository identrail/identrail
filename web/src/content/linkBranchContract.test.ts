import { describe, expect, it } from 'vitest';
import { FOOTER_NAV, siteLinks } from '../siteConfig';
import { TRUST_PROOF_LINKS } from './proofArtifacts';
import { DOC_ENTRIES } from './resources';

const repoBase = 'https://github.com/identrail/identrail/';

function assertNoMainBranchLink(link: string) {
  if (!link.startsWith(repoBase)) {
    return;
  }

  expect(link).not.toContain('/blob/main/');
  expect(link).not.toContain('/tree/main/');
}

const sourceFiles = import.meta.glob('../**/*.{ts,tsx}', {
  query: '?raw',
  import: 'default',
  eager: true
});

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

  it('does not hardcode non-existent main branch links in trust proof links', () => {
    for (const artifact of TRUST_PROOF_LINKS) {
      assertNoMainBranchLink(artifact.href);
    }
  });

  it('does not hardcode non-existent main branch links in footer nav', () => {
    for (const column of FOOTER_NAV) {
      for (const link of column.links) {
        assertNoMainBranchLink(link.to);
      }
    }
  });

  it('does not hardcode non-existent main branch links in any source file', () => {
    const mainBranchPattern = /https:\/\/github\.com\/identrail\/identrail\/(tree|blob)\/main(?:[/?#]|$)/g;
    const violations: string[] = [];

    for (const [filePath, content] of Object.entries(sourceFiles)) {
      if (filePath.includes('.test.')) {
        continue;
      }
      const matches = (content as string).match(mainBranchPattern);
      if (matches) {
        violations.push(`${filePath}: ${matches.join(', ')}`);
      }
    }

    expect(violations, `Found main branch links in source files:\n${violations.join('\n')}`).toHaveLength(0);
  });
});
