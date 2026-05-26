import { describe, expect, it } from 'vitest';
import { DOMAIN_ASSET_ORDER, DOMAIN_ASSETS, getDomainAsset, isDomainAssetKey } from './domainAssets';

describe('domain asset registry', () => {
  it('keeps the first app redesign domains in a stable section order', () => {
    expect(DOMAIN_ASSET_ORDER).toEqual(['aws', 'github', 'kubernetes']);
  });

  it('centralizes official provider logo paths and source references', () => {
    for (const key of DOMAIN_ASSET_ORDER) {
      const asset = DOMAIN_ASSETS[key];

      expect(asset.logoSrc).toBe(`/brand-logos/${key}.svg`);
      expect(asset.logoAlt).toMatch(asset.label === 'GitHub' ? /GitHub/ : new RegExp(asset.label, 'i'));
      expect(asset.officialSourceUrl).toMatch(/^https:\/\//);
      expect(asset.brandGuidanceUrl).toMatch(/^https:\/\//);
      expect(asset.primaryTone).toMatch(/^#[0-9a-f]{6}$/i);
      expect(asset.darkPanelTone).toBe('#080809');
    }
  });

  it('resolves known domains and rejects unsupported values', () => {
    expect(getDomainAsset('aws').officialSourceLabel).toBe('AWS Architecture Icons');
    expect(getDomainAsset('github').officialSourceLabel).toBe('GitHub Brand Toolkit');
    expect(getDomainAsset('kubernetes').officialSourceLabel).toBe('CNCF Kubernetes Artwork');
    expect(isDomainAssetKey('aws')).toBe(true);
    expect(isDomainAssetKey('azure')).toBe(false);
  });
});
