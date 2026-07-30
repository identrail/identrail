import { readFile } from 'node:fs/promises';

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const packageLock = JSON.parse(await readFile(new URL('../package-lock.json', import.meta.url), 'utf8'));
const declaredVersion = packageJson.devDependencies?.typescript;
const lockedVersion = packageLock.packages?.['node_modules/typescript']?.version;
const supportedVersion = '5.9.3';

if (declaredVersion !== supportedVersion || lockedVersion !== supportedVersion) {
  console.error(
    `Unsupported Vercel TypeScript toolchain: package.json=${declaredVersion ?? 'missing'}, ` +
      `package-lock.json=${lockedVersion ?? 'missing'}. Expected ${supportedVersion}. ` +
      'Upgrade only after a Vercel preview proves the new major is supported.'
  );
  process.exit(1);
}

console.log(`Vercel TypeScript toolchain verified: ${supportedVersion}`);
