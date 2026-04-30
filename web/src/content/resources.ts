export type DocEntry = {
  title: string;
  description: string;
  href: string;
  tags: string[];
};

export type BlogPost = {
  title: string;
  slug: string;
  description: string;
  category: string;
  readTime: string;
  intro: string[];
  sections: {
    heading: string;
    paragraphs: string[];
    bullets?: string[];
  }[];
  references: {
    label: string;
    href: string;
  }[];
};

export type FaqItem = {
  question: string;
  answer: string;
};

export const HOME_FAQ_ITEMS: FaqItem[] = [
  {
    question: 'Is the scan read-only?',
    answer:
      'Yes. Identrail discovery connectors are built for read-only collection of identity and trust-path metadata. You control write actions separately through staged policy workflows.'
  },
  {
    question: 'How does Identrail access AWS, Kubernetes, and GitHub data?',
    answer:
      'Identrail uses least-privilege service principals, IAM roles, and API tokens to collect machine identity metadata from AWS IAM, Kubernetes RBAC and service accounts, plus repository and workflow signals from Git providers.'
  },
  {
    question: 'What data is stored?',
    answer:
      'By default, Identrail stores graph metadata needed for trust-path analysis, findings, and remediation history. Sensitive values such as raw secrets are not required for core trust-path mapping.'
  },
  {
    question: 'Can we self-host?',
    answer:
      'Yes. The open-source core is designed for self-hosted evaluation and production environments. Teams can later adopt hosted SaaS or enterprise deployment models without re-platforming.'
  },
  {
    question: 'How does policy simulation avoid breaking production?',
    answer:
      'Policy simulation shows which workloads and trust paths would be affected before enforcement. Teams can roll out in stages, monitor impact, and use rollback controls if needed.'
  },
  {
    question: 'What integrations are supported?',
    answer:
      'Identrail supports AWS IAM, Kubernetes identities and RBAC, OIDC trust relationships, and Git-based repository/workflow telemetry. Enterprise workflows can connect ticketing and operational controls.'
  }
];

export const BLOG_POSTS: BlogPost[] = [
  {
    title: 'Machine Identity Security in 2026: A Practical Operating Model',
    slug: 'machine-identity-security-operating-model-2026',
    description:
      'The frameworks platform and security teams use to discover, prioritize, and control machine trust paths in production.',
    category: 'Machine Identity Security',
    readTime: '10 min',
    intro: [
      'Machine identity security is no longer a narrow IAM hygiene problem. In most modern environments, non-human identities span AWS roles, Kubernetes service accounts, GitHub Actions runners, OIDC trust relationships, secret stores, and internal service principals. Security teams usually review those systems in separate tools. Attackers do not.',
      'A practical operating model starts with one simple shift: stop asking whether a single identity is overprivileged in theory, and start asking which trust path can actually reach a sensitive resource in production. That framing is what separates a backlog of noisy findings from a program that reduces real blast radius.'
    ],
    sections: [
      {
        heading: 'Why the old model breaks down',
        paragraphs: [
          'Traditional reviews focus on static permissions. A role policy is inspected in AWS, an RBAC binding is checked in Kubernetes, and a workflow token is reviewed in GitHub. Each control may look reasonable in isolation. The risk appears when those identities can chain together across systems.',
          'A GitHub Actions workflow can mint an OIDC token, assume a cloud role, reach a workload identity, and then touch a production resource. If teams do not see that path end to end, they tend to either underreact to real risk or overreact with broad restrictions that break engineering workflows.'
        ],
        bullets: [
          'Static permission review misses cross-system identity chaining.',
          'Ownership is fragmented across platform, cloud, and security teams.',
          'The highest-risk paths usually involve automation, not humans.'
        ]
      },
      {
        heading: 'What a workable operating model looks like',
        paragraphs: [
          'The strongest programs do four things well. First, they continuously inventory machine identities and trust edges. Second, they map reachability from source identity to target resource. Third, they prioritize based on production impact, not just policy complexity. Fourth, they introduce controls in a staged way so the fix does not become the next outage.',
          'That means your core artifacts should be operational, not purely compliance-oriented: a trust graph snapshot, a list of high-risk reachable paths, evidence showing why a path exists, and a remediation plan that can be tested before enforcement.'
        ],
        bullets: [
          'Inventory identities and trust relationships continuously.',
          'Rank findings by reachable resource sensitivity and privilege depth.',
          'Simulate policy changes before rolling them out.',
          'Keep remediation evidence for auditors and engineering leaders.'
        ]
      },
      {
        heading: 'What good teams measure',
        paragraphs: [
          'Security leaders need metrics that connect identity posture to operational outcomes. Useful measures include the number of production-reachable paths, time to validate a risky path, time to remediate a high-severity chain, and the share of machine identities that have clear ownership.',
          'These metrics are more useful than vanity counts like total policies reviewed. They show whether the organization is getting faster at turning identity data into safer access.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail is built for this exact operating model. It discovers machine identities across AWS, Kubernetes, Git-based workflows, and OIDC trust boundaries, then maps the trust paths that matter in production.',
          'Instead of handing teams another list of detached configuration issues, Identrail helps them see the full path, understand blast radius, and tighten access in stages. That is what makes machine identity security operational rather than aspirational.'
        ]
      }
    ],
    references: [
      {
        label: 'NIST SP 800-207: Zero Trust Architecture',
        href: 'https://csrc.nist.gov/pubs/sp/800/207/final'
      },
      {
        label: 'AWS IAM Access Analyzer',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html'
      },
      {
        label: 'Amazon EKS IAM roles for service accounts',
        href: 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
      },
      {
        label: 'GitHub Actions OIDC for AWS',
        href: 'https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services'
      }
    ]
  },
  {
    title: 'AWS NHI Security: 14 Misconfigurations That Expand Blast Radius',
    slug: 'aws-nhi-security-misconfigurations',
    description:
      'A field guide to overprivileged IAM role chains, cross-account assumptions, and practical remediation patterns.',
    category: 'AWS Security',
    readTime: '8 min',
    intro: [
      'Most AWS machine identity incidents do not start with a spectacular exploit. They start with ordinary drift: a trust policy that became too broad, a role left reusable across workloads, a permissive cross-account path that nobody revisited after an integration went live.',
      'That is why AWS non-human identity security needs to be evaluated as path security. The real question is not whether one role is powerful. It is whether one machine principal can inherit, assume, or pivot into a chain that reaches something sensitive.'
    ],
    sections: [
      {
        heading: 'The misconfigurations that matter most',
        paragraphs: [
          'The common patterns are familiar. Wildcard principals in trust policies. Cross-account roles without strong conditions. GitHub OIDC trust relationships that only check the provider, not the repo or branch context. Workload roles that carry broad read or write permissions because it was easier than modeling the exact need.',
          'None of those are novel. The problem is that they accumulate silently. Teams see them as local exceptions, but attackers experience them as one connected privilege system.'
        ],
        bullets: [
          'Trust policies that accept more principals than intended.',
          'Reusable automation roles shared across unrelated systems.',
          'Cross-account assumptions without strong external or contextual constraints.',
          'High-value data plane permissions attached to general-purpose workload roles.'
        ]
      },
      {
        heading: 'Why static IAM review is not enough',
        paragraphs: [
          'A role can look acceptable when reviewed alone. The issue becomes obvious only when you attach the rest of the chain: who can mint the session, under what conditions, in which account, and what the assumed role can then reach.',
          'That is why mature AWS identity reviews combine policy analysis with reachability analysis. They do not stop at "can this role do X?" They continue to "which machine identities can get to this role, and which production resources sit behind it?"'
        ]
      },
      {
        heading: 'What remediation should look like',
        paragraphs: [
          'The right fix is usually narrower than teams fear. Tighten trust policy conditions. Break shared automation roles into environment-specific roles. Reduce broad data access permissions first, then shrink the rest over time. Use validation and simulation before rollout so the organization does not trade access risk for deployment risk.',
          'In practice, the most effective AWS remediation plans are prioritized. You do not need to rewrite all IAM policies in one quarter. You need to remove the highest-impact trust paths first.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail helps teams see AWS machine identity risk as a real path, not a disconnected policy file. It maps who can assume what, which role chain reaches which resources, and where blast radius expands across accounts and workloads.',
          'That lets cloud security teams focus on the misconfigurations that actually matter: reachable, production-relevant paths that can be fixed safely and explained clearly to engineering owners.'
        ]
      }
    ],
    references: [
      {
        label: 'AWS IAM policy evaluation logic',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html'
      },
      {
        label: 'AWS STS AssumeRole API reference',
        href: 'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html'
      },
      {
        label: 'AWS IAM best practices',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
      },
      {
        label: 'AWS IAM Access Analyzer findings',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings-view.html'
      }
    ]
  },
  {
    title: 'Kubernetes Machine Identity: RBAC Risk Paths You Can Actually Fix',
    slug: 'kubernetes-machine-identity-rbac-risk-paths',
    description:
      'How to map service account privilege escalations and implement rollout-safe policy tightening without downtime.',
    category: 'Kubernetes Security',
    readTime: '9 min',
    intro: [
      'Kubernetes machine identity problems are often described as RBAC sprawl. That is true, but incomplete. The harder problem is that Kubernetes access rarely stops at Kubernetes. A service account can trigger cloud access through workload identity, read secrets that unlock external systems, or operate inside a namespace that is less isolated than everyone assumed.',
      'That is why Kubernetes machine identity security has to move beyond single binding reviews. You need to understand which service accounts can actually reach privileged actions, sensitive namespaces, and external cloud resources.'
    ],
    sections: [
      {
        heading: 'The RBAC paths that deserve attention first',
        paragraphs: [
          'Teams usually find the same risky patterns. Default or broadly reused service accounts. Namespace-local roles that quietly include secret read or pod exec permissions. ClusterRoleBindings that were added for operational convenience and never narrowed later.',
          'The most dangerous cases are not always the ones with the longest YAML. They are the ones that combine Kubernetes permissions with another trust boundary, such as IRSA, external secret managers, or CI-issued deploy credentials.'
        ],
        bullets: [
          'Service accounts shared by multiple workloads.',
          'Bindings that allow secret read, pod exec, or workload creation.',
          'Cluster-wide access granted to namespaced automation.',
          'Cloud reachability attached to Kubernetes identities.'
        ]
      },
      {
        heading: 'Why fixes stall in real environments',
        paragraphs: [
          'Most platform teams know some RBAC is too broad. They delay fixes because they do not know what will break. A production cluster is full of hidden coupling: a job depends on one secret read, an operator still needs one cluster-scoped verb, a deployment pipeline assumes a legacy binding still exists.',
          'That means the bottleneck is not detection. It is confidence. Teams need a way to understand the path, model the impact, and tighten access without creating a service incident.'
        ]
      },
      {
        heading: 'A practical remediation sequence',
        paragraphs: [
          'The cleanest path is staged. Start with visibility into the service account, its RBAC grants, and any attached cloud identity. Group findings by production impact. Then reduce the highest-risk verbs first, especially secret access, workload creation, and cluster-wide permissions. Where possible, shift shared identities into workload-specific identities.',
          'This turns Kubernetes identity hardening into an engineering workflow. It becomes reviewable, testable, and much easier to prioritize.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail helps teams map Kubernetes service accounts as part of a larger trust graph. It connects RBAC exposure to the downstream cloud or data systems that make the finding materially risky.',
          'That matters because platform teams do not need another generic RBAC report. They need to know which service account paths matter first, what those paths can reach, and how to tighten them without downtime.'
        ]
      }
    ],
    references: [
      {
        label: 'Kubernetes service accounts',
        href: 'https://kubernetes.io/docs/concepts/security/service-accounts/'
      },
      {
        label: 'Kubernetes RBAC reference',
        href: 'https://kubernetes.io/docs/reference/access-authn-authz/rbac/'
      },
      {
        label: 'Kubernetes audit logging',
        href: 'https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/'
      },
      {
        label: 'Amazon EKS IAM roles for service accounts',
        href: 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
      }
    ]
  },
  {
    title: 'From Secrets Sprawl to Signal: Building a Repo Exposure Program',
    slug: 'repo-exposure-program-machine-identities',
    description:
      'How platform teams operationalize git credential leak findings and connect them to real machine identity risk.',
    category: 'Software Supply Chain',
    readTime: '7 min',
    intro: [
      'Repository exposure programs often start with a simple goal: find secrets before attackers do. That is necessary, but it is not the full job. The harder question is which exposed credential or workflow token can actually turn into machine identity reachability in production.',
      'Without that second layer, secret scanning becomes a noisy triage queue. Teams rotate tokens, close tickets, and still fail to reduce the trust paths that matter.'
    ],
    sections: [
      {
        heading: 'Why secret findings pile up',
        paragraphs: [
          'A leaked key or workflow credential is not equally dangerous in every context. One credential might be scoped to a sandbox. Another might let a CI job assume a production role. If the review process treats both findings the same, teams either burn time on low-value work or miss the urgent issue.',
          'The answer is to connect the repository finding to the identity path behind it. Which system issued the credential? Which trust relationship accepts it? Which role or service account can it reach? Which data plane permissions sit at the end?'
        ]
      },
      {
        heading: 'What a real repo exposure program should do',
        paragraphs: [
          'A mature program does more than detect strings. It classifies credentials, enriches them with source repository and workflow context, and links them to the infrastructure or identity systems they can influence.',
          'That is especially important for GitHub Actions and OIDC-based flows. In those environments, the secret itself may not be long-lived, but the workflow can still mint a token that reaches a powerful machine role if the trust relationship is too open.'
        ],
        bullets: [
          'Separate dormant leaks from production-reachable identity exposure.',
          'Track the repository, workflow, branch, and environment tied to a finding.',
          'Prioritize findings that map to cloud roles, service accounts, or high-value pipelines.'
        ]
      },
      {
        heading: 'How remediation gets better',
        paragraphs: [
          'Once findings are tied to trust paths, remediation becomes clearer. Sometimes the right move is still token rotation. Often the better long-term fix is narrowing the trust policy, reducing role scope, locking OIDC claims to specific repos or branches, or tightening environment protection rules.',
          'That is how platform teams move from a secrets program to a machine identity exposure program. The output is no longer "we found a secret." It becomes "this repository path can reach this production role."'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail connects repository exposure signals to the machine identity paths they can unlock. That gives security and platform teams the context they need to tell the difference between cleanup work and urgent exposure.',
          'In practice, that means teams can prioritize the small number of repository findings that truly expand blast radius instead of drowning in a flat stream of leaks.'
        ]
      }
    ],
    references: [
      {
        label: 'GitHub secret scanning overview',
        href: 'https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning'
      },
      {
        label: 'GitHub security hardening for Actions',
        href: 'https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions'
      },
      {
        label: 'GitHub OIDC security hardening',
        href: 'https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect'
      },
      {
        label: 'NIST SP 800-218: Secure Software Development Framework',
        href: 'https://csrc.nist.gov/pubs/sp/800/218/final'
      }
    ]
  },
  {
    title: 'Open-Core vs Closed Platforms in Machine Identity Security',
    slug: 'open-core-vs-closed-machine-identity-security',
    description:
      'A transparent analysis of architecture, control, and TCO tradeoffs for enterprise buyers evaluating vendors.',
    category: 'Buying Guide',
    readTime: '6 min',
    intro: [
      'Enterprise buyers evaluating machine identity platforms are usually balancing three pressures at once: time to value, control over deployment, and confidence in how decisions are made. That is why architecture matters as much as feature count.',
      'The core choice is often not open source versus commercial. It is whether the product gives you enough transparency to understand what it sees, why it flagged a path, and how a control change will affect production.'
    ],
    sections: [
      {
        heading: 'What closed platforms do well',
        paragraphs: [
          'Closed platforms often deliver fast onboarding, polished workflows, and strong commercial support. For some teams, that is exactly the right tradeoff. If the organization wants a hosted service with minimal operational ownership, a managed model can reduce the time required to get to an initial deployment.',
          'The downside appears later, when the buyer needs to explain how a finding was derived, fit the product into internal architecture constraints, or adapt the system to a more opinionated engineering environment.'
        ]
      },
      {
        heading: 'What open-core changes for the buyer',
        paragraphs: [
          'Open-core can reduce that black-box problem. It gives technical teams a clearer view of data collection, trust-path construction, and control boundaries, while still leaving room for commercial deployment models and enterprise features where they matter.',
          'That does not automatically make it cheaper or better. It does make it easier to evaluate on technical truth. You can inspect the architecture, test it in your own environment, and make a more informed decision about where you want managed versus self-managed responsibility.'
        ],
        bullets: [
          'Greater transparency into how findings and relationships are modeled.',
          'More flexibility for self-hosted evaluation or regulated environments.',
          'Easier collaboration between security and platform teams during rollout.'
        ]
      },
      {
        heading: 'What buyers should ask',
        paragraphs: [
          'The right buying questions are practical. Can the product explain why a path exists? Can it show what would change before enforcement? Can the team self-host if procurement or residency requirements demand it? Can engineering owners validate the output without trusting a black box?',
          'Those questions usually reveal more than a long comparison spreadsheet. In a category like machine identity security, operational confidence is part of the product.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail is designed as an open-core, developer-trustable platform. Teams can evaluate the core transparently, understand the trust graph and evidence model, and then choose whether open-source, hosted, or enterprise deployment fits their environment.',
          'That positioning matters because machine identity security only works when security teams and platform teams trust what the product is showing them. Transparency is not a nice-to-have. It is part of the control plane.'
        ]
      }
    ],
    references: [
      {
        label: 'NIST SP 800-218: Secure Software Development Framework',
        href: 'https://csrc.nist.gov/pubs/sp/800/218/final'
      },
      {
        label: 'CISA Secure by Design',
        href: 'https://www.cisa.gov/securebydesign'
      },
      {
        label: 'OpenSSF',
        href: 'https://openssf.org/'
      }
    ]
  },
  {
    title: 'How to Prove Least Privilege for Non-Human Identities to Auditors',
    slug: 'least-privilege-evidence-for-non-human-identities',
    description:
      'Generate evidence for SOC 2 and ISO 27001 with trust graph snapshots, policy simulations, and remediation trails.',
    category: 'Compliance',
    readTime: '11 min',
    intro: [
      'Most audit pain around machine identities comes from one gap: teams can state least privilege as a policy goal, but they cannot produce clear evidence that it is true in practice. Screenshots of policies and access reviews are not enough when non-human identities move across cloud, cluster, CI, and secret-management boundaries.',
      'Auditors are usually looking for a simple chain of reasoning. What identities exist? What can they reach? How is access reviewed? How are risky permissions reduced safely? The more explainable your answers are, the easier the audit becomes.'
    ],
    sections: [
      {
        heading: 'What evidence is actually useful',
        paragraphs: [
          'Useful least-privilege evidence combines current state, change control, and proof of review. A trust graph snapshot shows current reachability. A simulation or validation artifact shows how a change was tested before rollout. A remediation trail shows the finding was closed intentionally rather than accidentally disappearing from a dashboard.',
          'This is why flat entitlement exports are rarely persuasive on their own. They list permissions, but they do not show the path from identity to sensitive target or the operational process used to reduce that path.'
        ],
        bullets: [
          'Current-state trust-path evidence.',
          'Owner and review history.',
          'Before-and-after policy comparison.',
          'Remediation timeline tied to a ticket or change event.'
        ]
      },
      {
        heading: 'How to make least privilege reviewable',
        paragraphs: [
          'The fastest way to improve audit readiness is to standardize what "review" means. Teams should define a short set of artifacts for high-risk machine identities: source principal, trust relationship, reachable sensitive target, current justification, and planned reduction if the path is broader than intended.',
          'This creates a consistent operating record. It also helps engineering teams because the audit artifact becomes the same artifact they use for prioritization and remediation.'
        ]
      },
      {
        heading: 'Why simulation matters',
        paragraphs: [
          'Auditors increasingly care about control effectiveness, not just the existence of a policy. If a team can show that a trust change was simulated, staged, and reviewed before enforcement, that demonstrates a stronger control process than a one-time manual edit.',
          'It also makes the evidence more believable. Least privilege is easier to defend when you can show how the organization reduces access without breaking production.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail turns least-privilege evidence into an operational artifact. It shows which machine identity path exists today, why it is risky, and what control change is being proposed before the change is enforced.',
          'That makes the same system useful for both sides of the house: security gets defensible evidence, and platform teams get a safer workflow for tightening access over time.'
        ]
      }
    ],
    references: [
      {
        label: 'NIST SP 800-53 AC-6 Least Privilege',
        href: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'
      },
      {
        label: 'NIST SP 800-207: Zero Trust Architecture',
        href: 'https://csrc.nist.gov/pubs/sp/800/207/final'
      },
      {
        label: 'AWS IAM Access Analyzer',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html'
      },
      {
        label: 'Kubernetes audit logging',
        href: 'https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/'
      }
    ]
  },
  {
    title: 'Designing Rollout-Safe Authorization Controls for Platform Teams',
    slug: 'rollout-safe-authorization-controls',
    description:
      'Staged policy rollouts, simulation gates, and kill-switch patterns that reduce authz outage risk in production.',
    category: 'Platform Engineering',
    readTime: '8 min',
    intro: [
      'Most teams do not avoid authorization hardening because they disagree with the goal. They avoid it because access changes can break production in ways that are hard to predict. That is especially true when machine identities span multiple systems and ownership is distributed.',
      'A rollout-safe authorization program is really a software delivery discipline. It treats policy changes like production changes: scoped, previewed, staged, monitored, and reversible.'
    ],
    sections: [
      {
        heading: 'What makes auth changes risky',
        paragraphs: [
          'Authorization failures are rarely visible until a workload tries to do real work. A role assumption fails during deploy. A service account loses access to one secret. A CI job can still read a repo but can no longer publish an artifact. The control is technically tighter, but the operational effect is an incident.',
          'That is why good teams do not jump straight from finding to enforcement. They validate the proposed change in the context of the workload and the path it serves.'
        ]
      },
      {
        heading: 'The staged rollout pattern',
        paragraphs: [
          'The most reliable pattern is simple: identify the risky path, simulate the narrower access, roll out to one bounded environment or identity set, monitor impact, and keep a rollback path. If the first stage is clean, continue to the next stage. If it is not, you have learned something without taking out production.',
          'This applies across AWS IAM, Kubernetes authorization, and CI/OIDC-based trust. The implementation details differ, but the operating model is the same.'
        ],
        bullets: [
          'Preview before enforcement.',
          'Roll out in small scopes first.',
          'Monitor for auth failures tied to the change.',
          'Preserve a fast rollback or temporary bypass.'
        ]
      },
      {
        heading: 'Why platform teams should own the workflow',
        paragraphs: [
          'Security should set the risk bar and priorities. Platform teams usually own the deployment mechanics and the confidence model. When both sides share the same evidence and rollout sequence, authorization hardening stops being a political exercise and becomes an engineering one.',
          'That is usually the difference between a quarterly permissions cleanup and a continuous control program.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail is designed around rollout-safe control changes. It does not stop at surfacing a risky path. It helps teams inspect the path, understand the likely impact of tightening it, and sequence the remediation in a way engineering can actually execute.',
          'That matters because the hardest part of authorization is not seeing the risk. It is removing the risk without breaking the system that depends on it.'
        ]
      }
    ],
    references: [
      {
        label: 'AWS IAM policy simulator',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html'
      },
      {
        label: 'Kubernetes dry-run',
        href: 'https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run'
      },
      {
        label: 'GitHub deployment environments',
        href: 'https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment'
      },
      {
        label: 'Open Policy Agent',
        href: 'https://www.openpolicyagent.org/docs/latest/'
      }
    ]
  },
  {
    title: 'Trust Graphs for Security Leaders: What to Measure and Why',
    slug: 'trust-graph-metrics-for-security-leaders',
    description:
      'Metrics that connect machine identity posture improvements to incident reduction and executive risk reporting.',
    category: 'Security Leadership',
    readTime: '7 min',
    intro: [
      'Security leaders do not need more raw machine identity data. They need a way to explain whether identity risk is shrinking, where exposure is concentrated, and whether engineering teams are getting faster at fixing the right problems.',
      'Trust graphs can help, but only if they are tied to decisions. The point is not to admire the graph. The point is to make blast radius, ownership, and remediation progress visible enough to manage.'
    ],
    sections: [
      {
        heading: 'The metrics worth putting in front of leadership',
        paragraphs: [
          'The most useful machine identity metrics are path-oriented. How many high-severity trust paths reach production-sensitive resources? How many of those paths are unowned? How long does it take to validate and remediate one? How often do new risky paths appear because a delivery workflow or integration changed?',
          'Those metrics are better than raw identity counts because they connect posture to exposure. A graph with 20,000 identities is not a problem by itself. A graph with 40 unreviewed production-reachable paths is.'
        ],
        bullets: [
          'High-severity production-reachable trust paths.',
          'Mean time to validate a reported path.',
          'Mean time to remediate high-impact findings.',
          'Share of paths with clear owner and remediation state.'
        ]
      },
      {
        heading: 'What not to over-index on',
        paragraphs: [
          'Leaders should be careful with metrics that are easy to count but hard to interpret. Total IAM policies, total service accounts, or total findings can all move in the wrong direction for good reasons. More infrastructure usually means more identities.',
          'What matters is whether the organization is reducing unnecessary reachability and getting faster at acting on material findings.'
        ]
      },
      {
        heading: 'How to use the metrics operationally',
        paragraphs: [
          'The best reporting rhythm is simple: identify the most exposed trust chains, show trend movement, and tie that to a short list of remediation outcomes. Executives get clarity on risk reduction. Engineering teams see which actions changed the number, not just the narrative.',
          'When done well, trust-graph reporting becomes a bridge between security and platform leadership. It turns identity risk from an abstract governance topic into a measurable engineering problem.'
        ]
      },
      {
        heading: 'Where Identrail fits',
        paragraphs: [
          'Identrail gives leadership a trust-path view that can be reported without losing technical credibility. It shows which machine identity chains reach sensitive systems, how those paths are changing over time, and which remediation actions are reducing real blast radius.',
          'That creates a much stronger story than generic entitlement dashboards. Leaders can talk about exposure, ownership, and control effectiveness using evidence the engineering teams actually trust.'
        ]
      }
    ],
    references: [
      {
        label: 'NIST SP 800-207: Zero Trust Architecture',
        href: 'https://csrc.nist.gov/pubs/sp/800/207/final'
      },
      {
        label: 'CISA Secure by Design',
        href: 'https://www.cisa.gov/securebydesign'
      },
      {
        label: 'AWS IAM Access Analyzer',
        href: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html'
      }
    ]
  }
];

export const DOC_ENTRIES: DocEntry[] = [
  {
    title: 'Quickstart on Docker',
    description: 'Deploy Identrail locally in under 10 minutes using Docker Compose.',
    href: 'https://github.com/identrail/identrail/blob/dev/deploy/docker/README.md',
    tags: ['quickstart', 'docker', 'self-hosted']
  },
  {
    title: 'Deploy Anywhere Runbook',
    description: 'Production deployment guidance for Kubernetes, Helm, Terraform, and systemd.',
    href: 'https://github.com/identrail/identrail/blob/dev/docs/deployment-anywhere.md',
    tags: ['deployment', 'kubernetes', 'terraform']
  },
  {
    title: 'Architecture Deep Dive',
    description: 'Understand ingestion pipelines, trust graph construction, and authorization controls.',
    href: 'https://github.com/identrail/identrail/blob/dev/docs/architecture.md',
    tags: ['architecture', 'graph', 'platform']
  },
  {
    title: 'AWS Collector',
    description: 'Collector configuration, permissions, and scaling tips for IAM role and policy discovery.',
    href: 'https://github.com/identrail/identrail/blob/dev/docs/aws-collector.md',
    tags: ['aws', 'iam', 'collector']
  },
  {
    title: 'Repo Exposure Scanner',
    description: 'Scan Git repositories for credential leaks and machine identity exposure patterns.',
    href: 'https://github.com/identrail/identrail/blob/dev/docs/repo-exposure.md',
    tags: ['git', 'secrets', 'scanner']
  },
  {
    title: 'Security Hardening Guide',
    description: 'Hardening checklist, supply chain controls, and incident response guidance.',
    href: 'https://github.com/identrail/identrail/blob/dev/docs/security-hardening.md',
    tags: ['security', 'hardening', 'operations']
  }
];
