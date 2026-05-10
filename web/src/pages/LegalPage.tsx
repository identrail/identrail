import { ReactNode } from 'react';
import { PageHero } from '../components/ui/PageHero';

type LegalKind = 'privacy' | 'terms' | 'privacy-choices';

type LegalDoc = {
  eyebrow: string;
  title: string;
  effectiveOn: string;
  body: ReactNode;
};

const DOCS: Record<LegalKind, LegalDoc> = {
  privacy: {
    eyebrow: 'Legal',
    title: 'Privacy policy',
    effectiveOn: 'Effective date: 2026-05-09',
    body: (
      <>
        <p>
          This policy explains how Identrail, Inc. (“Identrail”) collects and processes personal data when you visit
          our website at <a href="https://www.identrail.com">identrail.com</a> or use our hosted product. We collect
          the minimum data needed to operate the service and we do not sell personal data.
        </p>

        <h2>Data we collect</h2>
        <ul>
          <li>
            <strong>Account data</strong> - name, work email, employer, role. Used to authenticate you, contact you
            about service updates, and bill you when applicable.
          </li>
          <li>
            <strong>Usage data</strong> - page views and product events, processed via Google Analytics 4 and
            PostHog with IP-truncation enabled. Used to understand which features matter and which pages need
            rewriting.
          </li>
          <li>
            <strong>Tenant data</strong> - the trust-graph metadata you connect to Identrail (identities, roles,
            policies, RBAC bindings). Stored in your tenant only. Not used to train any model.
          </li>
        </ul>

        <h2>Where data is processed</h2>
        <p>
          Hosted Team customers pick US (us-east-1) or EU (eu-west-1) at sign-up. Enterprise customers pick a
          region or run a private deployment. Self-host customers process all data in their own environment.
        </p>

        <h2>Sharing</h2>
        <p>
          We use a small number of subprocessors (cloud hosting, email delivery, analytics, error tracking). The
          current list is available on request via{' '}
          <a href="mailto:privacy@identrail.com">privacy@identrail.com</a>. We do not sell personal data to third
          parties.
        </p>

        <h2>Your rights</h2>
        <p>
          If the GDPR or comparable laws apply to you, you have rights of access, correction, deletion, and
          portability. Email <a href="mailto:privacy@identrail.com">privacy@identrail.com</a> and we will respond
          within 30 days.
        </p>

        <h2>Contact</h2>
        <p>
          Questions? <a href="mailto:privacy@identrail.com">privacy@identrail.com</a>. We will respond within one
          business day.
        </p>
      </>
    )
  },
  terms: {
    eyebrow: 'Legal',
    title: 'Terms of service',
    effectiveOn: 'Effective date: 2026-05-09',
    body: (
      <>
        <p>
          These terms govern your use of Identrail's website and hosted services. By using either, you agree to
          these terms. Enterprise customers operate under a separate Master Service Agreement that supersedes this
          page.
        </p>

        <h2>Use of the service</h2>
        <p>
          You may use Identrail to discover, monitor, and remediate machine-identity risk in environments you have
          authorisation to assess. You may not use Identrail to access systems you are not authorised to assess,
          to interfere with the service, or to circumvent technical limits.
        </p>

        <h2>Accounts</h2>
        <p>
          You are responsible for the accuracy of account information and for the actions of users in your
          workspace. Notify us promptly of unauthorised access at{' '}
          <a href="mailto:security@identrail.com">security@identrail.com</a>.
        </p>

        <h2>Open-source components</h2>
        <p>
          The Identrail open-source edition is licensed under Apache 2.0. The source license governs use of the
          self-hosted edition. These terms apply to the hosted service.
        </p>

        <h2>Service availability</h2>
        <p>
          We aim for high availability but do not guarantee uninterrupted service on the free or Team plans.
          Enterprise customers receive a custom SLA.
        </p>

        <h2>Liability</h2>
        <p>
          To the fullest extent permitted by law, Identrail's aggregate liability under these terms is limited to
          the fees you paid in the twelve months preceding the claim, or USD 100, whichever is greater. Some
          jurisdictions do not allow limitations on certain liabilities; in those jurisdictions our liability is
          limited to the minimum permitted.
        </p>

        <h2>Changes</h2>
        <p>
          We may update these terms; we will post a notice on this page and email account owners ahead of any
          material change.
        </p>

        <h2>Contact</h2>
        <p>
          <a href="mailto:hello@identrail.com">hello@identrail.com</a>.
        </p>
      </>
    )
  },
  'privacy-choices': {
    eyebrow: 'Legal',
    title: 'Privacy choices',
    effectiveOn: 'Effective date: 2026-05-09',
    body: (
      <>
        <p>
          You can adjust how Identrail processes your personal data. The choices below apply to website visits;
          tenant-data choices for hosted customers are managed inside the product.
        </p>

        <h2>Analytics</h2>
        <p>
          We use Google Analytics 4 and PostHog with IP truncation enabled. To opt out of analytics in this
          browser, install the{' '}
          <a href="https://tools.google.com/dlpage/gaoptout" target="_blank" rel="noopener noreferrer">
            Google Analytics opt-out add-on
          </a>{' '}
          or use a privacy-focused browser. We respect Global Privacy Control (GPC) signals.
        </p>

        <h2>Marketing emails</h2>
        <p>
          We do not run a marketing email list yet. If we add one, every message will include a one-click
          unsubscribe.
        </p>

        <h2>Data subject requests</h2>
        <p>
          Email <a href="mailto:privacy@identrail.com">privacy@identrail.com</a> with the subject line "Data
          request" - we respond within 30 days.
        </p>
      </>
    )
  }
};

export function LegalPage({ kind }: { kind: LegalKind }) {
  const doc = DOCS[kind];
  return (
    <>
      <PageHero eyebrow={doc.eyebrow} title={doc.title} lede={doc.effectiveOn} />
      <article className="container article prose">{doc.body}</article>
    </>
  );
}
