export async function workspaceMemberID(identity: string): Promise<string> {
  const normalizedIdentity = identity.trim().toLowerCase();
  if (!normalizedIdentity) {
    throw new Error('An email address or user ID is required to create a workspace member ID.');
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error('Secure workspace member IDs are not supported in this browser.');
  }

  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(normalizedIdentity));
  const token = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `member-${token}`;
}
