import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const beforePolicy = `{
  "Effect": "Allow",
  "Action": ["sts:AssumeRole", "s3:*"],
  "Resource": "*"
}`;

const afterPolicy = `{
  "Effect": "Allow",
  "Action": ["sts:AssumeRole", "s3:GetObject"],
  "Resource": [
    "arn:aws:s3:::prod-artifacts/*"
  ]
}`;

export function TrustGraphAgentSection() {
  return (
    <section className="section reveal-on-scroll" aria-labelledby="agent-title">
      <div className="section-card agent-section">
        <div className="agent-copy">
          <p className="eyebrow eyebrow-dark">Remediation Planning</p>
          <h2 id="agent-title">Meet the Identrail Trust Graph Agent</h2>
          <p>
            Plan machine identity remediation with guided trust-path analysis.
            Review least-privilege change suggestions and simulated pull-request policy diffs before operator approval.
          </p>
          <div className="agent-steps" aria-hidden="true">
            <span>Analyze graph</span>
            <span>Review fix</span>
            <span>Approve plan</span>
          </div>
          <SafeLink className="btn btn-primary" href={siteLinks.agentRelease}>
            Star the repo to follow future agent workflow releases
          </SafeLink>
        </div>

        <div className="agent-pr-preview" aria-label="Agent remediation pull request preview">
          <div className="agent-icon" aria-hidden="true">
            <span className="agent-eye" />
            <span className="agent-eye" />
          </div>
          <div className="agent-snippet-grid">
            <article>
              <p>Before</p>
              <pre>
                <code>{beforePolicy}</code>
              </pre>
            </article>
            <article>
              <p>After</p>
              <pre>
                <code>{afterPolicy}</code>
              </pre>
            </article>
          </div>
        </div>
      </div>
    </section>
  );
}
