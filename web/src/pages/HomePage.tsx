import { HomeHero } from '../components/home/Hero';
import { StackStrip } from '../components/home/StackStrip';
import { Capabilities } from '../components/home/Capabilities';
import { FieldInsights } from '../components/home/FieldInsights';
import { OpenSourceProof } from '../components/home/OpenSourceProof';
import { FounderQuote } from '../components/home/FounderQuote';
import { Comparison } from '../components/home/Comparison';
import { CtaBanner } from '../components/CtaBanner';

/**
 * Marketing home page.
 *
 * Composition order is the narrative:
 *   1. Hero — promise + one designed product surface
 *   2. Stack strip — what we cover (replaces "trusted by")
 *   3. Capabilities — Discover · Detect · Remediate
 *   4. Field insights — public industry numbers (testimonial substitute)
 *   5. Open-source proof — repo metrics, license, code-review surface
 *   6. Founder quote — why this exists (testimonial substitute)
 *   7. Comparison — Identrail vs. closed alternatives
 *   8. Closing CTA
 */
export function HomePage() {
  return (
    <>
      <HomeHero />
      <StackStrip />
      <Capabilities />
      <FieldInsights />
      <OpenSourceProof />
      <FounderQuote />
      <Comparison />
      <CtaBanner
        eyebrow="Get started"
        title="Map your first production trust path in under ten minutes."
        body="Connect read-only, see the paths that reach your sensitive data, simulate the smallest fix. No write access, no agent, no obligation."
        primary={{ label: 'Start a free risk scan', to: '/demo' }}
        secondary={{ label: 'Compare plans', to: '/pricing' }}
      />
    </>
  );
}
