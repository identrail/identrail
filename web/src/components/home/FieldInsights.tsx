import { SectionHeader } from '../ui/Section';

/**
 * "From the field" — a creative substitute for testimonials we don't have yet.
 *
 * The product surfaces these patterns every week. Each insight is sourced
 * to a public, citable industry report so the section can stand alongside
 * a customer wall once we have one. Numbers are conservative and link back
 * to the underlying source.
 */
type Insight = {
  number: string;
  title: string;
  body: string;
  source: string;
  href: string;
};

const INSIGHTS: Insight[] = [
  {
    number: '46×',
    title: 'Machine identities now outnumber humans',
    body:
      'In the average enterprise, non-human identities outnumber human users by roughly 46 to one — and most of them have never been reviewed.',
    source: 'CyberArk Identity Security Threat Landscape 2024',
    href: 'https://www.cyberark.com/threat-landscape/'
  },
  {
    number: '74%',
    title: 'Identity-related breaches involve a privileged or service identity',
    body:
      'Three in four identity breaches in the last year traced back to a service account, OIDC token or workload identity that had more access than anyone realised.',
    source: 'Identity Defined Security Alliance, 2024 Trends in Securing Digital Identities',
    href: 'https://www.idsalliance.org/'
  },
  {
    number: '54%',
    title: 'Of cloud breaches start at a misconfigured identity',
    body:
      'Misconfigured IAM roles, over-permissive trust policies, and stale machine credentials remain the most common initial-access vector in public-cloud incidents.',
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
          title="The numbers we built Identrail around."
          lede="Until we have customer stories to tell, here is the public evidence that machine-identity risk is real, growing, and under-tooled. Identrail surfaces these patterns inside your own environment."
        />
        <div className="grid grid-3">
          {INSIGHTS.map((i) => (
            <article className="insight" key={i.title}>
              <div className="stat-num">{i.number}</div>
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
