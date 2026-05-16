import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import { mfaErrorMessage, normalizeCompletedSessionRedirect, normalizeReturnTo } from './WorkOSMFAPage';

describe('WorkOSMFAPage helpers', () => {
  it('normalizes return_to to same-origin app paths only', () => {
    window.history.pushState({}, '', '/auth/mfa');
    const origin = window.location.origin;

    expect(normalizeReturnTo('/app/tenant-a/workspace-a?tab=scan#findings')).toBe(
      '/app/tenant-a/workspace-a?tab=scan#findings'
    );
    expect(normalizeReturnTo(`${origin}/app/tenant-a`)).toBe('/app/tenant-a');
    expect(normalizeReturnTo('https://evil.example/app/tenant-a')).toBe('/app');
    expect(normalizeReturnTo('javascript:alert(1)')).toBe('/app');
    expect(normalizeReturnTo('/signin')).toBe('/app');
  });

  it('keeps completed-session redirects same-origin', () => {
    window.history.pushState({}, '', '/auth/mfa');
    const origin = window.location.origin;

    expect(normalizeCompletedSessionRedirect('/onboarding/org')).toBe('/onboarding/org');
    expect(normalizeCompletedSessionRedirect(`${origin}/app`)).toBe('/app');
    expect(normalizeCompletedSessionRedirect('https://evil.example/app')).toBe('/app');
  });

  it('preserves API verification errors instead of rewriting every unauthorized response', () => {
    expect(mfaErrorMessage(new ApiError('invalid verification code', 401))).toBe('invalid verification code');
    expect(mfaErrorMessage(new ApiError('mfa session expired', 401))).toBe(
      'This verification session expired. Start sign-in again.'
    );
  });
});
