import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { apiClient, type OnboardingState } from '../../api/client';
import { SkipForNow } from '../../components/onboarding/SkipForNow';
import { workspaceMemberID } from '../../utils/workspaceMemberID';
import {
  FEATURE_ONBOARDING_WIZARD,
  OnboardingFrame,
  loadOrStartOnboardingResponse,
  onboardingAuth,
  routeAfterOnboardingResponse,
  routeToOnboardingStep
} from './onboardingUtils';

const EMAIL_LOCAL_ATOM_CHARACTER_PATTERN = /^(?:[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]|[^\p{ASCII}\p{C}\p{Z}])$/u;
const EMAIL_DOMAIN_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const EMAIL_DOMAIN_CHARACTERS_PATTERN = /^[\p{L}\p{M}\p{N}.\u3002\uFF0E\uFF61-]+$/u;
// Quoted local parts allow printable text and backslash-escaped ASCII characters.
const EMAIL_QUOTED_LOCAL_PART_PATTERN = /^"(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|[^\p{ASCII}\p{C}\p{Z}]|\\[\x20-\x7e])*"$/u;

function isValidEmailLocalPart(localPart: string): boolean {
  if (localPart.startsWith('"')) {
    return EMAIL_QUOTED_LOCAL_PART_PATTERN.test(localPart);
  }
  return localPart.split('.').every((atom) => {
    return atom.length > 0 && Array.from(atom).every((character) => EMAIL_LOCAL_ATOM_CHARACTER_PATTERN.test(character));
  });
}

function normalizeEmailDomain(domain: string): string | null {
  if (!EMAIL_DOMAIN_CHARACTERS_PATTERN.test(domain)) {
    return null;
  }
  try {
    return new URL(`http://${domain}`).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function isValidIpv4AddressLiteral(address: string): boolean {
  const octets = address.split('.');
  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
  );
}

function isValidIpv6AddressLiteral(address: string): boolean {
  if (!/^[\da-f:.]+$/i.test(address)) {
    return false;
  }
  try {
    new URL(`http://[${address}]`);
    return true;
  } catch {
    return false;
  }
}

function isValidEmailAddressLiteral(domain: string): boolean {
  if (!domain.startsWith('[') || !domain.endsWith(']')) {
    return false;
  }
  const address = domain.slice(1, -1);
  if (isValidIpv4AddressLiteral(address)) {
    return true;
  }
  const ipv6Prefix = 'ipv6:';
  return (
    address.slice(0, ipv6Prefix.length).toLowerCase() === ipv6Prefix &&
    isValidIpv6AddressLiteral(address.slice(ipv6Prefix.length))
  );
}

function isValidInviteEmail(email: string): boolean {
  // A quoted local part may contain @; the final one separates the domain.
  const separator = email.lastIndexOf('@');
  if (separator < 1) {
    return false;
  }
  const localPart = email.slice(0, separator);
  const domain = email.slice(separator + 1);
  if (!domain || !isValidEmailLocalPart(localPart)) {
    return false;
  }
  const localPartByteLength = new TextEncoder().encode(localPart).length;
  if (localPartByteLength > 64) {
    return false;
  }
  if (domain.startsWith('[') || domain.endsWith(']')) {
    return isValidEmailAddressLiteral(domain) && localPartByteLength + domain.length + 1 <= 254;
  }
  const asciiDomain = normalizeEmailDomain(domain);
  if (!asciiDomain) {
    return false;
  }
  const labels = asciiDomain.split('.');
  const topLevelDomain = labels[labels.length - 1] ?? '';
  return (
    localPartByteLength + asciiDomain.length + 1 <= 254 &&
    labels.length > 1 &&
    labels.every((label) => EMAIL_DOMAIN_LABEL_PATTERN.test(label)) &&
    /^[a-z0-9-]{2,63}$/i.test(topLevelDomain) &&
    /[a-z]/i.test(topLevelDomain)
  );
}

function splitInviteEmailTokens(value: string): string[] {
  const tokens: string[] = [];
  let token = '';
  let quoted = false;
  let escaped = false;

  for (const character of value) {
    if (!quoted && /[\s,;]/u.test(character)) {
      if (token) tokens.push(token);
      token = '';
      continue;
    }
    token += character;
    if (escaped) {
      escaped = false;
    } else if (quoted && character === '\\') {
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
    }
  }
  if (token) tokens.push(token);
  return tokens;
}

function parseInviteEmails(value: string): { invitees: string[]; invalidEmails: string[] } {
  const tokens = splitInviteEmailTokens(value)
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  const invitees = new Set<string>();
  const invalidEmails = new Set<string>();

  for (const token of tokens) {
    if (isValidInviteEmail(token)) {
      invitees.add(token);
    } else {
      invalidEmails.add(token);
    }
  }

  return { invitees: Array.from(invitees), invalidEmails: Array.from(invalidEmails) };
}

export function InvitePage() {
  const navigate = useNavigate();
  const [state, setState] = useState<OnboardingState | null>(null);
  const [emails, setEmails] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [emailsError, setEmailsError] = useState('');
  const { invitees, invalidEmails } = useMemo(() => parseInviteEmails(emails), [emails]);

  useEffect(() => {
    if (!FEATURE_ONBOARDING_WIZARD) {
      return;
    }
    let mounted = true;
    const run = async () => {
      setLoading(true);
      setError('');
      try {
        const response = await loadOrStartOnboardingResponse();
        const nextState = response.state;
        if (!mounted) {
          return;
        }
        setState(nextState);
        if (!nextState.org_id || !nextState.workspace_id) {
          navigate('/onboarding/workspace', { replace: true });
          return;
        }
        if (routeToOnboardingStep(navigate, response, '/onboarding/invite', '/onboarding/invite')) {
          return;
        }
      } catch (requestError) {
        if (!mounted) {
          return;
        }
        setError(requestError instanceof Error ? requestError.message : 'Unable to load invite step.');
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };
    void run();
    return () => {
      mounted = false;
    };
  }, [navigate]);

  if (!FEATURE_ONBOARDING_WIZARD) {
    return <Navigate to="/app" replace />;
  }

  const complete = async () => {
    setError('');
    setEmailsError('');
    if (invalidEmails.length) {
      setEmailsError(`Correct or remove invalid email addresses before continuing: ${invalidEmails.join(', ')}`);
      return;
    }
    setSaving(true);
    try {
      const response = await apiClient.completeOnboarding();
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/app');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to complete onboarding.');
    } finally {
      setSaving(false);
    }
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setEmailsError('');
    if (!state?.workspace_id) {
      setError('Workspace context is required before inviting teammates.');
      return;
    }
    if (invalidEmails.length) {
      setEmailsError(`Correct or remove invalid email addresses before continuing: ${invalidEmails.join(', ')}`);
      return;
    }
    if (!invitees.length) {
      setEmailsError('Enter at least one valid email address.');
      return;
    }
    setSaving(true);
    try {
      const auth = onboardingAuth(state);
      const inviteRecords = await Promise.all(
        invitees.map(async (email) => ({ email, memberID: await workspaceMemberID(email) }))
      );
      for (const { email, memberID } of inviteRecords) {
        await apiClient.upsertWorkspaceMember(
          state.workspace_id,
          {
            member_id: memberID,
            user_id: email,
            email,
            role: 'viewer',
            status: 'invited'
          },
          auth
        );
      }
      const response = await apiClient.completeOnboarding();
      setState(response.state);
      routeAfterOnboardingResponse(navigate, response.redirect_path, '/app');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Unable to invite teammates.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <OnboardingFrame
      step="invite"
      title="Invite team"
    >
      {loading ? <p className="idt-muted-strong">Preparing invite controls...</p> : null}
      {error ? (
        <div className="idt-auth-alert" role="alert">
          {error}
        </div>
      ) : null}
      <form className="idt-onboarding-form" onSubmit={submit}>
        <div className="idt-onboarding-field">
          <label htmlFor="invite-emails">Email addresses</label>
          <div className={emailsError ? 'idt-onboarding-input-wrap has-error' : 'idt-onboarding-input-wrap'}>
            <textarea
              id="invite-emails"
              value={emails}
              onChange={(event) => {
                setEmails(event.target.value);
                if (emailsError) {
                  setEmailsError('');
                }
              }}
              rows={5}
              aria-describedby={emailsError ? 'invite-emails-hint invite-emails-error' : 'invite-emails-hint'}
              aria-invalid={emailsError ? 'true' : undefined}
            />
            {emailsError ? (
              <span id="invite-emails-error" className="idt-onboarding-input-error" role="alert">
                {emailsError}
              </span>
            ) : null}
          </div>
          <p id="invite-emails-hint" className="idt-muted">
            Separate addresses with commas, semicolons, or new lines.
          </p>
        </div>
        <div className="idt-onboarding-actions">
          <button type="submit" className="idt-btn idt-btn-primary" disabled={saving || loading}>
            {saving ? 'Finishing...' : 'Invite and finish'}
          </button>
          <SkipForNow disabled={saving || loading} onSkip={complete} label="Finish without invites" />
        </div>
      </form>
    </OnboardingFrame>
  );
}
