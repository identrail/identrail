import assert from 'node:assert/strict';
import test from 'node:test';

import {
  extractIssueReferences,
  sanitizeMarkdown,
  validateAWSEpicPullRequest,
} from './validate_aws_epic_pr.mjs';

function event({ base = 'dev', body = '', title = 'Test PR' } = {}) {
  return {
    pull_request: {
      title,
      body,
      base: { ref: base },
    },
  };
}

const guardrailMaintenanceFiles = [
  '.github/branch-protection/dev.json',
  '.github/workflows/aws-epic-pr-guard.yml',
  'CHANGELOG.md',
  'docs/aws-platform-dependency-index.md',
  'scripts/validate_aws_epic_pr.mjs',
  'scripts/validate_aws_epic_pr.test.mjs',
];

test('ignores unrelated pull requests', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Closes #901',
    })
  );

  assert.equal(result.valid, true);
  assert.equal(result.applicable, false);
});

test('allows a parent guardrail maintenance PR that references the epic without closing it', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Refs #1472',
    }),
    { changedFiles: guardrailMaintenanceFiles }
  );

  assert.equal(result.valid, true);
  assert.equal(result.applicable, true);
});

test('rejects parent-only AWS epic PRs when changed files are unavailable', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Refs #1472',
    })
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /reference exactly one focused child issue; found none/);
});

test('rejects parent-only AWS epic PRs that change implementation files', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Refs #1472',
    }),
    {
      changedFiles: [
        '.github/workflows/aws-epic-pr-guard.yml',
        'internal/aws/collector.go',
      ],
    }
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /limited to AWS epic guardrail maintenance files/);
});

test('allows one AWS child issue to close from dev while referencing the parent epic', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: ['Closes: #1477', 'Refs #1472'].join('\n'),
    })
  );

  assert.equal(result.valid, true);
});

test('rejects closing the parent epic', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Closes #1472',
    })
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /Do not close #1472/);
});

test('rejects closing the parent epic from a commit message', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: ['Closes #1477', 'Refs #1472'].join('\n'),
    }),
    {
      commitMessages: 'add collector\n\nCloses: #1472',
    }
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /Do not close #1472/);
});

test('rejects AWS platform PRs that do not target dev', () => {
  const result = validateAWSEpicPullRequest(
    event({
      base: 'main',
      body: 'Closes #1477',
    })
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /must target dev/);
});

test('rejects multiple AWS child issues in one PR', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Closes #1477 and #1478',
    })
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /exactly one focused child issue/);
});

test('rejects child references that do not close the focused child issue', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Refs #1477',
    })
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /must close exactly one child issue/);
});

test('does not accept a child-closing keyword from commit messages only', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: 'Refs #1472',
    }),
    {
      commitMessages: 'add collector\n\nCloses #1477',
    }
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /in the PR body/);
});

test('detects bare AWS issue mentions as non-closing references', () => {
  const result = validateAWSEpicPullRequest(
    event({
      base: 'main',
      body: 'Related: #1477',
    })
  );

  assert.equal(result.applicable, true);
  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /must target dev/);
  assert.match(result.failures.join('\n'), /must close exactly one child issue/);
});

test('does not accept a child-closing keyword from the title only', () => {
  const result = validateAWSEpicPullRequest(
    event({
      title: 'Closes #1477',
      body: 'Refs #1472',
    })
  );

  assert.equal(result.valid, false);
  assert.match(result.failures.join('\n'), /in the PR body/);
});

test('extracts qualified and URL issue references outside code examples', () => {
  const references = extractIssueReferences(
    [
      'Closes identrail/identrail#1477',
      'Refs https://github.com/identrail/identrail/issues/1472',
      'Related: #1480',
      'Closes some-org/some-repo#1478',
      'Refs https://github.com/some-org/some-repo/issues/1479',
      '`Closes #1478`',
      '```',
      'Closes #1479',
      '```',
    ].join('\n')
  );

  assert.deepEqual(
    references.map((reference) => [reference.keyword, reference.issueNumber, reference.closing]),
    [
      ['closes', 1477, true],
      ['refs', 1472, false],
      ['mention', 1480, false],
    ]
  );
});

test('sanitizes comments and code before policy extraction', () => {
  assert.equal(
    sanitizeMarkdown('Refs #1472 <!-- Closes #1477 --> `Closes #1478`').trim(),
    'Refs #1472'
  );
});

test('ignores Cubic generated summaries appended to the PR body', () => {
  const result = validateAWSEpicPullRequest(
    event({
      body: [
        'Refs #1472',
        '<!-- This is an auto-generated description by cubic. -->',
        'Validator rules: PRs must not close #1472.',
        '<!-- End of auto-generated description by cubic. -->',
      ].join('\n'),
    }),
    { changedFiles: guardrailMaintenanceFiles }
  );

  assert.equal(result.valid, true);
});
