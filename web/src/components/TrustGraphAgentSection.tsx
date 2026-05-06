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
    <section className="idt-section idt-shell" aria-labelledby="agent-title">
      <div className="idt-card-grid two-col">
        <article className="idt-card">
          <p className="idt-eyebrow">Remediation Planning</p>
          <h2 id="agent-title">Meet the Identrail Trust Graph Agent</h2>
          <p>
            Plan machine identity remediation with guided trust-path analysis.
            Review least-privilege change suggestions and simulated pull-request policy diffs before operator approval.
          </p>
          <div className="idt-command-steps" aria-hidden="true">
            <span>Analyze graph</span>
            <span>Review fix</span>
            <span>Approve plan</span>
          </div>
          <SafeLink className="idt-btn idt-btn-primary" href={siteLinks.agentRelease}>
            Star the repo to follow future agent workflow releases
          </SafeLink>
        </article>

        <article className="idt-card" aria-label="Agent remediation pull request preview">
          <div className="idt-command-list" aria-hidden="true">
            <span className="idt-command-label">Before</span>
            <pre>
              <code>{beforePolicy}</code>
            </pre>
          </div>
          <div className="idt-command-list" aria-hidden="true">
            <span className="idt-command-label">After</span>
            <pre>
              <code>{afterPolicy}</code>
            </pre>
          </div>
        </article>
      </div>
    </section>
  );
}
