#!/usr/bin/env node
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export const AWS_EPIC_PARENT_ISSUE = 1472;
export const AWS_EPIC_FIRST_CHILD_ISSUE = 1473;
export const AWS_EPIC_LAST_CHILD_ISSUE = 1557;
export const AWS_EPIC_REPOSITORY = 'identrail/identrail';
export const AWS_EPIC_GUARDRAIL_MAINTENANCE_FILES = new Set([
  '.github/branch-protection/dev.json',
  '.github/workflows/aws-epic-pr-guard.yml',
  'CHANGELOG.md',
  'docs/aws-platform-dependency-index.md',
  'scripts/validate_aws_epic_pr.mjs',
  'scripts/validate_aws_epic_pr.test.mjs',
]);

const AWS_EPIC_GUARDRAIL_CORE_FILES = new Set([
  '.github/workflows/aws-epic-pr-guard.yml',
  'scripts/validate_aws_epic_pr.mjs',
  'scripts/validate_aws_epic_pr.test.mjs',
]);

const closingKeywords = new Set([
  'close',
  'closed',
  'closes',
  'fix',
  'fixed',
  'fixes',
  'resolve',
  'resolved',
  'resolves',
]);

const issueRefPattern =
  /(?:#\d+|[\w.-]+\/[\w.-]+#\d+|https?:\/\/github\.com\/[\w.-]+\/[\w.-]+\/issues\/\d+)/gi;
const issueReferenceGroupPattern =
  /\b(close[sd]?|fix(?:e[sd])?|resolve[sd]?|refs?)\s*:?\s+((?:(?:#\d+|[\w.-]+\/[\w.-]+#\d+|https?:\/\/github\.com\/[\w.-]+\/[\w.-]+\/issues\/\d+)(?:\s*(?:,|and|&)\s*)?)+)/gi;

export function sanitizeMarkdown(text = '') {
  return text
    .replace(
      /<!--\s*This is an auto-generated description by cubic\.\s*-->[\s\S]*?(?:<!--\s*End of auto-generated description by cubic\.\s*-->|$)/gi,
      ' '
    )
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]*`/g, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');
}

export function issueNumberFromReference(reference, repository = AWS_EPIC_REPOSITORY) {
  const normalizedRepository = repository.toLowerCase();
  const value = String(reference);
  const unqualifiedMatch = value.match(/^#(\d+)$/);
  if (unqualifiedMatch) {
    return Number.parseInt(unqualifiedMatch[1], 10);
  }

  const qualifiedMatch = value.match(/^([\w.-]+\/[\w.-]+)#(\d+)$/i);
  if (qualifiedMatch) {
    return qualifiedMatch[1].toLowerCase() === normalizedRepository
      ? Number.parseInt(qualifiedMatch[2], 10)
      : null;
  }

  const urlMatch = value.match(/^https?:\/\/github\.com\/([\w.-]+\/[\w.-]+)\/issues\/(\d+)$/i);
  if (urlMatch) {
    return urlMatch[1].toLowerCase() === normalizedRepository
      ? Number.parseInt(urlMatch[2], 10)
      : null;
  }

  return null;
}

export function extractIssueReferences(text = '') {
  const sanitized = sanitizeMarkdown(text);
  const references = [];
  const keywordReferenceRanges = new Set();

  for (const match of sanitized.matchAll(issueReferenceGroupPattern)) {
    const keyword = match[1].toLowerCase();
    const issueRefsText = match[2];
    const issueRefsOffset = match.index + match[0].indexOf(issueRefsText);

    for (const issueRefMatch of issueRefsText.matchAll(issueRefPattern)) {
      const issueRef = issueRefMatch[0];
      const issueNumber = issueNumberFromReference(issueRef);
      if (!Number.isInteger(issueNumber)) {
        continue;
      }
      const start = issueRefsOffset + issueRefMatch.index;
      keywordReferenceRanges.add(`${start}:${start + issueRef.length}`);
      references.push({
        keyword,
        issueNumber,
        closing: closingKeywords.has(keyword),
      });
    }
  }

  for (const match of sanitized.matchAll(issueRefPattern)) {
    const issueRef = match[0];
    const issueNumber = issueNumberFromReference(issueRef);
    if (!Number.isInteger(issueNumber)) {
      continue;
    }

    const rangeKey = `${match.index}:${match.index + issueRef.length}`;
    if (keywordReferenceRanges.has(rangeKey)) {
      continue;
    }

    references.push({
      keyword: 'mention',
      issueNumber,
      closing: false,
    });
  }

  return references;
}

function uniqueNumbers(references) {
  return [...new Set(references.map((reference) => reference.issueNumber))].sort((a, b) => a - b);
}

function formatIssueList(issueNumbers) {
  return issueNumbers.map((issueNumber) => `#${issueNumber}`).join(', ');
}

function normalizeChangedFiles(changedFiles = []) {
  if (!Array.isArray(changedFiles)) {
    return [];
  }

  return changedFiles.map((changedFile) => String(changedFile).trim()).filter(Boolean);
}

function normalizeText(value = '') {
  if (Array.isArray(value)) {
    return value.join('\n');
  }

  return String(value || '');
}

export function isGuardrailMaintenanceChange(changedFiles = []) {
  const normalizedFiles = normalizeChangedFiles(changedFiles);
  return (
    normalizedFiles.length > 0 &&
    normalizedFiles.every((changedFile) => AWS_EPIC_GUARDRAIL_MAINTENANCE_FILES.has(changedFile)) &&
    normalizedFiles.some((changedFile) => AWS_EPIC_GUARDRAIL_CORE_FILES.has(changedFile))
  );
}

export function validateAWSEpicPullRequest(event, options = {}) {
  const pullRequest = event?.pull_request ?? event?.pullRequest ?? {};
  const title = pullRequest.title || '';
  const body = pullRequest.body || '';
  const baseRef = pullRequest.base?.ref || pullRequest.baseRefName || event?.base_ref || '';
  const changedFiles = normalizeChangedFiles(options.changedFiles);
  const commitMessages = normalizeText(options.commitMessages);
  const bodyReferences = extractIssueReferences(body);
  const titleReferences = extractIssueReferences(title);
  const commitReferences = extractIssueReferences(commitMessages);
  const allReferences = [...bodyReferences, ...titleReferences, ...commitReferences];
  const parentReferences = allReferences.filter(
    (reference) => reference.issueNumber === AWS_EPIC_PARENT_ISSUE
  );
  const childReferences = allReferences.filter(
    (reference) =>
      reference.issueNumber >= AWS_EPIC_FIRST_CHILD_ISSUE &&
      reference.issueNumber <= AWS_EPIC_LAST_CHILD_ISSUE
  );
  const bodyChildReferences = bodyReferences.filter(
    (reference) =>
      reference.issueNumber >= AWS_EPIC_FIRST_CHILD_ISSUE &&
      reference.issueNumber <= AWS_EPIC_LAST_CHILD_ISSUE
  );
  const uniqueChildIssues = uniqueNumbers(childReferences);
  const closingChildIssues = uniqueNumbers(bodyChildReferences.filter((reference) => reference.closing));
  const parentOnlyGuardrailMaintenance =
    parentReferences.length > 0 &&
    uniqueChildIssues.length === 0 &&
    isGuardrailMaintenanceChange(changedFiles);

  const failures = [];
  const awsEpicReferenced = parentReferences.length > 0 || childReferences.length > 0;
  if (!awsEpicReferenced) {
    return {
      valid: true,
      applicable: false,
      failures,
      summary: 'No AWS platform parent or child issue references were found.',
    };
  }

  if (baseRef !== 'dev') {
    failures.push(
      `AWS platform PRs must target dev because #1472 requires future PRs to start from origin/dev; found base ${baseRef || '<unknown>'}.`
    );
  }

  if (parentReferences.some((reference) => reference.closing)) {
    failures.push(
      'Do not close #1472 from a child or guardrail PR. The AWS platform parent epic should be referenced with "Refs #1472" until the full program is complete.'
    );
  }

  if (!parentOnlyGuardrailMaintenance) {
    if (uniqueChildIssues.length !== 1) {
      failures.push(
        `AWS platform PRs must reference exactly one focused child issue; found ${formatIssueList(uniqueChildIssues) || 'none'}. Parent-only PRs are allowed only when the change is limited to AWS epic guardrail maintenance files.`
      );
    }

    if (closingChildIssues.length !== 1) {
      failures.push(
        `AWS platform PRs must close exactly one child issue in the PR body with Closes/Fixes/Resolves; found ${formatIssueList(closingChildIssues) || 'none'}.`
      );
    } else if (uniqueChildIssues.length === 1 && closingChildIssues[0] !== uniqueChildIssues[0]) {
      failures.push(
        `The closing child issue ${formatIssueList(closingChildIssues)} must match the only referenced AWS child issue ${formatIssueList(uniqueChildIssues)}.`
      );
    }
  }

  return {
    valid: failures.length === 0,
    applicable: true,
    failures,
    summary:
      uniqueChildIssues.length > 0
        ? `AWS platform child refs: ${formatIssueList(uniqueChildIssues)}.`
        : parentOnlyGuardrailMaintenance
          ? 'AWS platform parent guardrail maintenance ref only.'
          : 'AWS platform parent ref only.',
  };
}

function readChangedFiles(path) {
  if (!path) {
    return [];
  }

  return fs
    .readFileSync(path, 'utf8')
    .split(/\r?\n/)
    .map((changedFile) => changedFile.trim())
    .filter(Boolean);
}

function readOptionalText(path) {
  if (!path) {
    return '';
  }

  return fs.readFileSync(path, 'utf8');
}

function readEvent(path) {
  if (!path) {
    throw new Error('Missing event JSON path. Pass a path or set GITHUB_EVENT_PATH.');
  }
  return JSON.parse(fs.readFileSync(path, 'utf8'));
}

export function main(argv = process.argv) {
  const eventPath = argv[2] || process.env.GITHUB_EVENT_PATH;
  const changedFilesPath = argv[3] || process.env.AWS_EPIC_CHANGED_FILES_PATH;
  const commitMessagesPath = argv[4] || process.env.AWS_EPIC_COMMIT_MESSAGES_PATH;
  const result = validateAWSEpicPullRequest(readEvent(eventPath), {
    changedFiles: readChangedFiles(changedFilesPath),
    commitMessages: readOptionalText(commitMessagesPath),
  });

  console.log(result.summary);
  if (!result.valid) {
    for (const failure of result.failures) {
      console.error(`- ${failure}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(
    result.applicable
      ? 'AWS platform PR discipline is satisfied.'
      : 'AWS platform PR discipline is not applicable.'
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
