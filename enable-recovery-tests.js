#!/usr/bin/env node
/**
 * Utility script to enable all recovery tests by replacing it.skip with it
 */

import { readFileSync, writeFileSync } from 'fs';
import { glob } from 'glob';

const testFiles = glob.sync('src/__tests__/phase3/recovery/*.test.ts');

console.log(`Found ${testFiles.length} test files to update...`);

for (const file of testFiles) {
  console.log(`Processing ${file}...`);
  let content = readFileSync(file, 'utf-8');

  // Count replacements
  const matches = content.match(/it\.skip\(/g);
  const count = matches ? matches.length : 0;

  // Replace it.skip with it
  content = content.replace(/it\.skip\(/g, 'it(');

  writeFileSync(file, content, 'utf-8');
  console.log(`  ✓ Enabled ${count} tests`);
}

console.log('\nAll recovery tests enabled!');
