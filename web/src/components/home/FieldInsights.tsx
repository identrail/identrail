import { SectionHeader } from '../ui/Section';

/**
 * "From the field" — a creative substitute for testimonials we don't have yet.
 *
 * We intentionally avoid fragile market statistics here. The cards point to
 * public signals and explain the risk pattern without presenting third-party
 * numbers as Identrail-owned proof.
 */
type Insight = {
  signal: string;
  title: string;
  body: string;
  source: string;
  href: string;
};

const INSIGHTS: Insight[] = [
  {
    signal: 'Signal 01',
    title: 'Machine identities keep multiplying faster than review capacity',
    body:
      'Cloud roles, workload identities, CI tokens and service accounts now sit across every delivery path. Identrail focuses on what those identities can actually reach.',
    source: 'CyberArk Identity Security Threat Landscape 2024',
    href: 'https://www.cyberark.com/threat-landscape/'
  },
  {
    signal: 'Signal 02',
    title: 'Privileged access is no longer just a human-account problem',
    body:
      'Service accounts, workload federation and automation tokens can inherit broad privileges. Identrail ties each risk to the source identity and the target resource.',
    source: 'Identity Defined Security Alliance, 2024 Trends in Securing Digital Identities',
    href: 'https://www.idsalliance.org/'
  },
  {
    signal: 'Signal 03',
    title: 'Cloud exposure often starts as an identity configuration problem',
    body:
      'Overbroad trust policies, stale roles and permissive claims are hard to reason about in isolation. Identrail resolves them as reachable paths.',
    source: 'Verizon DBIR 2024',
    href: 'https://www.verizon.com/business/resources/reports/dbir/'
  }
];

export function FieldInsights() {
  return (
    <section className="section">
      <div className="container">
        <SectionHeader
          eyebrow="From the field"
          title="The risk patterns Identrail turns into evidence."
          lede="Until we have customer stories to tell, here are the public risk patterns Identrail was built to make concrete inside your own environment."
        />
        <div className="grid grid-3">
          {INSIGHTS.map((i) => (
            <article className="insight" key={i.title}>
              <div className="stat-num">{i.signal}</div>
              <h3>{i.title}</h3>
              <p>{i.body}</p>
              <cite>
                <a href={i.href} target="_blank" rel="noopener noreferrer">
                  {i.source}
                </a>
              </cite>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
