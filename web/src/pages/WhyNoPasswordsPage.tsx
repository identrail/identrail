import { Link } from 'react-router-dom';

export function WhyNoPasswordsPage() {
  return (
    <section className="idt-passwordless-page">
      <div className="idt-passwordless-hero">
        <p className="idt-app-kicker">Passwordless by design</p>
        <h1>Identrail keeps passwords out of the blast radius.</h1>
        <p>
          Machine identity security belongs behind strong identity providers, short-lived server sessions, and account
          controls users can understand.
        </p>
        <div className="idt-inline-actions">
          <Link className="idt-btn idt-btn-primary" to="/signin">
            Sign In
          </Link>
          <Link className="idt-btn idt-btn-ghost" to="/signup">
            Sign Up
          </Link>
        </div>
      </div>

      <div className="idt-passwordless-grid">
        <article>
          <span>01</span>
          <h2>Use the source of truth</h2>
          <p>Google, GitHub, and enterprise SSO already own identity proofing, recovery, and policy enforcement.</p>
        </article>
        <article>
          <span>02</span>
          <h2>Reduce stored secrets</h2>
          <p>Identrail stores an opaque session record and never needs to handle a reusable account password.</p>
        </article>
        <article>
          <span>03</span>
          <h2>Make session control visible</h2>
          <p>Every browser session can be reviewed and revoked from the account security page.</p>
        </article>
      </div>
    </section>
  );
}
