import { describe, expect, it } from 'vitest';
import { ApiError } from '../api/client';
import { emailVerificationErrorMessage } from './WorkOSEmailVerificationPage';

describe('WorkOSEmailVerificationPage helpers', () => {
  it('preserves API verification errors instead of rewriting every unauthorized response', () => {
    expect(emailVerificationErrorMessage(new ApiError('invalid verification code', 401))).toBe(
      'invalid verification code'
    );
    expect(emailVerificationErrorMessage(new ApiError('email verification session expired', 401))).toBe(
      'This verification session expired. Start sign-in again to receive a new code.'
    );
  });

  it('falls back to a generic message for unknown failures', () => {
    expect(emailVerificationErrorMessage('boom')).toBe('Unable to continue verification.');
    expect(emailVerificationErrorMessage(new Error('network down'))).toBe('network down');
  });
});
