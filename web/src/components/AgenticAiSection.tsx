import { siteLinks } from '../siteConfig';
import { SafeLink } from './SafeLink';

const controls = [
  'Define candidate controls for agent identities, tool tokens, and delegated trust paths',
  'Model potential privilege-escalation routes from agent to infrastructure',
  'Plan policy guardrails before future agent authorization changes reach production'
];

export function AgenticAiSection() {
  return (
    <section className="idt-section idt-shell" aria-labelledby="agentic-title">
      <div className="idt-section-title">
        <p className="idt-eyebrow">Built for Modern Workloads</p>
        <h2 id="agentic-title">Agentic AI Security Roadmap</h2>
        <p>
          This section describes roadmap direction for agent identity governance across model providers,
          orchestration layers, and runtime infrastructure.
        </p>
        <SafeLink className="idt-btn idt-btn-primary" href={siteLinks.agenticAiRoadmap}>
          Explore Roadmap Notes
        </SafeLink>
      </div>

      <ul className="idt-card-grid two-col" aria-label="Agentic AI roadmap focus areas">
        {controls.map((control) => (
          <li key={control} className="idt-card">
            {control}
          </li>
        ))}
      </ul>
    </section>
  );
}
