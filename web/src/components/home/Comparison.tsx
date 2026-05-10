import { SectionHeader } from '../ui/Section';

const ROWS = [
  {
    capability: 'Trust-path explainability',
    identrail: 'Full chain: identity → privilege → workload → resource, with evidence.',
    closed: 'Risk score on a finding; chain is not surfaced.'
  },
  {
    capability: 'Rollout safety',
    identrail: 'Read-only ingest; simulated remediation; staged enforcement built in.',
    closed: 'Hardening is a write op handed to a separate tool, with no simulator.'
  },
  {
    capability: 'Open-core architecture',
    identrail: 'Apache 2.0. Full source on GitHub. Self-host the same binary we run.',
    closed: 'Closed source. Black-box detection logic. Audit-by-vendor-promise.'
  },
  {
    capability: 'Who owns the fix',
    identrail: 'Identrail names the resource owner and routes the playbook to them.',
    closed: 'Findings dropped into a security queue with no automatic owner mapping.'
  },
  {
    capability: 'Cost shape',
    identrail: 'Free self-host. Hosted plan starts at $19/user/mo. No enterprise floor for SAML.',
    closed: 'Sales-led pricing. SSO and core controls behind enterprise tier.'
  }
];

export function Comparison() {
  return (
    <section className="section">
      <div className="container">
        <SectionHeader
          eyebrow="Why teams choose Identrail"
          title="What changes when the trust graph is open."
          lede="The closed alternatives in this category trade transparency for a steeper enterprise price. We made the opposite trade."
        />
        <table className="compare">
          <thead>
            <tr>
              <th scope="col">Capability</th>
              <th scope="col">Identrail</th>
              <th scope="col">Typical closed alternative</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((r) => (
              <tr key={r.capability}>
                <th scope="row">{r.capability}</th>
                <td data-col="Identrail" className="v-strong">
                  {r.identrail}
                </td>
                <td data-col="Closed alternative" className="no">
                  {r.closed}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
