import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const controls = [
  'Define candidate controls for agent identities, tool tokens, and delegated trust paths',
  'Model potential privilege-escalation routes from agent to infrastructure',
  'Plan policy guardrails before future agent authorization changes reach production'
];

export function AgenticAiSection() {
  return (
    <section className="section" aria-labelledby="agentic-title">
      <div className="agentic-section">
        <div>
          <p className="eyebrow">Built for Modern Workloads</p>
          <h2 id="agentic-title">Agentic AI Security Roadmap</h2>
          <p>
            This section describes roadmap direction for agent identity governance across model
            providers, orchestration layers, and runtime infrastructure.
          </p>
          <SafeLink className="btn btn-primary" href={siteLinks.agenticAi}>
            Explore Roadmap Notes
          </SafeLink>
        </div>
        <ul>
          {controls.map((control) => (
            <li key={control}>{control}</li>
          ))}
        </ul>
      </div>
    </section>
  );
}
