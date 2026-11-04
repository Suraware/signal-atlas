import { test, expect, type Page } from '@playwright/test';
import { executableFixture, literalLibrary, literalSymbol, type ExecutableFixture } from './executable-fixtures';

const observations = new WeakMap<Page, { errors: string[]; remote: string[] }>();
test.beforeEach(async ({ page }) => {
  const observed = { errors: [] as string[], remote: [] as string[] };
  observations.set(page, observed);
  page.on('pageerror', error => observed.errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error') observed.errors.push(message.text()); });
  page.on('request', request => {
    if (!request.url().startsWith('http://127.0.0.1:8732/')) observed.remote.push(request.url());
  });
  await page.goto('/#/lab');
  await expect(page.getByRole('heading', { name: 'Analysis lab', exact: true })).toBeVisible();
});
test.afterEach(async ({ page }) => {
  expect(observations.get(page)?.errors).toEqual([]);
  expect(observations.get(page)?.remote).toEqual([]);
});

async function upload(page: Page, kind: ExecutableFixture) {
  const response = page.waitForResponse(response => response.url().endsWith('/api/analyze') && response.request().method() === 'POST');
  await page.getByLabel('File to inspect', { exact: true }).setInputFiles({
    name: `${kind}.bin`, mimeType: 'application/octet-stream', buffer: executableFixture(kind),
  });
  await page.getByRole('button', { name: 'Inspect file', exact: true }).click();
  const result = await response;
  expect(result.status()).toBe(200);
  return result.json();
}

async function noPageOverflow(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
}

for (const kind of ['pe32', 'pe64'] as const) {
  test(`real PE upload (${kind}) shows structured imports separately from API string bait`, async ({ page }) => {
    const result = await upload(page, kind);
    expect(result.executable.imports.symbols[0].name).toBe('CreateFileW');
    const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
    await expect(structure.getByRole('heading', { name: 'Executable structure', exact: true })).toBeVisible();
    await expect(structure.getByText('Parsed selected structures', { exact: true })).toBeVisible();
    const entry = structure.getByRole('region', { name: 'Entry point', exact: true });
    await expect(entry.getByText('0x210', { exact: true })).toBeVisible();
    await expect(entry.getByText(kind === 'pe64' ? '0x140001010' : '0x401010', { exact: true })).toBeVisible();
    await expect(structure.getByRole('table', { name: /Declared sections/ }).getByRole('row').filter({ hasText: '.text' })).toContainText('Read, Execute');
    await expect(structure.getByRole('table', { name: 'Decoded library records', exact: true })).toContainText('KERNEL32.dll');
    const summary = structure.locator('summary').filter({ hasText: 'Imported symbols (2)' });
    await summary.focus();
    await page.keyboard.press('Enter');
    const symbols = structure.getByRole('table', { name: 'Decoded imported or undefined symbols', exact: true });
    await expect(symbols).toContainText('CreateFileW');
    await expect(symbols).toContainText('Ordinal 7');
    await expect(symbols).toContainText('0x440');
    await expect(symbols).not.toContainText('VirtualAllocEx');
    await expect(page.getByRole('heading', { name: 'Static review leads', exact: true })).toBeVisible();
    await expect(page.getByRole('figure', { name: /Entropy map/ })).toBeVisible();
    await noPageOverflow(page);
  });
}

for (const kind of ['elf32', 'elf64', 'elf64-big'] as const) {
  test(`real ELF upload (${kind}) keeps dependency libraries separate from undefined symbol providers`, async ({ page }) => {
    const result = await upload(page, kind);
    expect(result.executable.imports.symbols[0].library).toBeNull();
    const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
    await expect(structure).toBeVisible();
    await expect(structure.getByRole('table', { name: 'Declared load segments', exact: true })).toContainText('PT_LOAD 0');
    await expect(structure.getByRole('table', { name: 'Decoded library records', exact: true })).toContainText('libfixture.so');
    await structure.locator('summary').filter({ hasText: 'Imported symbols (2)' }).click();
    const symbols = structure.getByRole('table', { name: 'Decoded imported or undefined symbols', exact: true });
    await expect(symbols).toContainText('puts');
    await expect(symbols).toContainText('optional_hook');
    await expect(symbols).toContainText('Provider not resolved');
    await expect(symbols).toContainText('WEAK');
    await expect(symbols).not.toContainText('libfixture.so');
    await expect(symbols).not.toContainText('defined_symbol');
    await expect(symbols).not.toContainText('VirtualAllocEx');
    await noPageOverflow(page);
  });
}

test('sectionless ELF preserves load and dependency evidence with a visible partial-symbol explanation', async ({ page }) => {
  await upload(page, 'sectionless');
  const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
  await expect(structure.getByText('Partial structure', { exact: true })).toBeVisible();
  await expect(structure.getByRole('table', { name: 'Decoded library records', exact: true })).toContainText('libfixture.so');
  await expect(structure.getByRole('heading', { name: 'Decoding warnings', exact: true })).toBeVisible();
  await expect(structure).toContainText('section-based symbol decoding is unavailable or partial');
  await expect(structure).toContainText('No symbol records decoded');
  await expect(structure.getByRole('table', { name: /Declared sections/ })).toHaveCount(0);
});

for (const kind of ['invalid-pe', 'invalid-elf'] as const) {
  test(`invalid executable (${kind}) shows decoding failure while preserving fingerprints and whole-file coverage`, async ({ page }) => {
    await upload(page, kind);
    const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
    await expect(structure.getByText('Invalid structure', { exact: true })).toBeVisible();
    await expect(structure.getByRole('heading', { name: 'Decoding warnings', exact: true })).toBeVisible();
    await expect(structure.getByRole('region', { name: 'Entry point', exact: true })).toContainText('No proven file offset');
    await expect(page.getByRole('heading', { name: 'File fingerprints', exact: true })).toBeVisible();
    await expect(page.getByText(/Whole file scanned/)).toBeVisible();
  });
}

test('partial PE rejects ambiguous imports and leaves an unmapped entry without a fake offset', async ({ page }) => {
  const result = await upload(page, 'partial-pe');
  expect(result.executable.entry_point.mapping).toBe('unmapped');
  const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
  await expect(structure.getByText('Partial structure', { exact: true })).toBeVisible();
  await expect(structure.getByRole('heading', { name: 'Decoding warnings', exact: true })).toBeVisible();
  await expect(structure.getByRole('table', { name: 'Decoded library records', exact: true })).toHaveCount(0);
  const entry = structure.getByRole('region', { name: 'Entry point', exact: true });
  await expect(entry).toContainText('Unmapped address');
  await expect(entry).toContainText('No proven file offset');
  await expect(structure).toContainText('ambiguous mapping');
  await expect(structure).toContainText('No symbol records decoded');
  await expect(structure.getByRole('listitem').filter({ hasText: 'Section declares write and execute' })).toContainText('0x188');
});

for (const [kind, address] of [['overflow-pe32', '0x1000000f0'], ['overflow-pe64', '0x100000000000000f0']] as const) {
  test(`overflowed header entry (${kind}) retains its exact address but never claims a file mapping`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 1000 });
    const result = await upload(page, kind);
    expect(result.executable.entry_point).toMatchObject({ address, offset: null, mapping: 'unavailable' });
    const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
    await expect(structure.getByText('Partial structure', { exact: true })).toBeVisible();
    await expect(structure.getByRole('region', { name: 'Decoding warnings', exact: true })).toContainText('PE header range overflows');
    const entry = structure.getByRole('region', { name: 'Entry point', exact: true });
    await expect(entry.getByText(address, { exact: true })).toBeVisible();
    await expect(entry).toContainText('Mapping unavailable');
    await expect(entry).toContainText('No proven file offset');
    await noPageOverflow(page);
  });
}

test('invalid section data offsets stay declared while flag evidence points to the available header', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 1000 });
  const result = await upload(page, 'invalid-range-pe');
  expect(result.executable.findings.find((finding: { code: string }) => finding.code === 'writable_executable_section').offset).toBe('0x188');
  const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
  const section = structure.getByRole('table', { name: /Declared sections/ }).getByRole('row').filter({ hasText: '.bad' });
  await expect(section).toContainText('0xffffff00');
  await expect(section).toContainText('Invalid range');
  const finding = structure.getByRole('region', { name: 'Structural observations', exact: true }).getByRole('listitem').filter({ hasText: 'Section declares write and execute' });
  await expect(finding).toContainText('0x188');
  await expect(finding).not.toContainText('0xffffff00');
  await noPageOverflow(page);
});

test('wide declared ELF values stay exact in the real JSON and interface without JavaScript rounding', async ({ page }) => {
  const result = await upload(page, 'wide-elf');
  expect(result.executable.sections_declared).toBe('9223372036854775815');
  const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
  await expect(structure).toContainText('9,223,372,036,854,775,815');
  await expect(structure).toContainText('9,223,372,036,854,775,809');
  await expect(structure).toContainText('0xfffffffffffffff0');
  await noPageOverflow(page);
});

test('reached import limits and actual parser work remain visible and keyboard-operable', async ({ page }) => {
  const result = await upload(page, 'limited-pe');
  expect(result.executable.coverage.symbol_records_read).toBe(601);
  const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
  await expect(structure).toContainText('Only the first 512 imported-symbol records');
  const limits = structure.locator('summary').filter({ hasText: 'Parser limits and coverage' });
  await limits.focus();
  await page.keyboard.press('Enter');
  await expect(structure.getByText('601 / 20,000', { exact: true })).toBeVisible();
  await expect(structure.getByText('Imported symbols retained', { exact: true })).toBeVisible();
  const symbols = structure.locator('summary').filter({ hasText: 'Imported symbols (512)' });
  await symbols.focus();
  await page.keyboard.press('Enter');
  await expect(structure.getByRole('table', { name: 'Decoded imported or undefined symbols', exact: true }).getByRole('row')).toHaveCount(513);
});

for (const width of [1440, 720, 390]) {
  test(`long literal executable names remain text and reflow inside named tables at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    await upload(page, 'literal-pe');
    const structure = page.getByRole('region', { name: 'Executable structure', exact: true });
    await expect(structure.getByRole('region', { name: 'Imported libraries', exact: true }).getByText(literalLibrary, { exact: true })).toBeVisible();
    await structure.locator('summary').filter({ hasText: 'Imported symbols (2)' }).click();
    await expect(structure.getByRole('region', { name: 'Imported symbols', exact: true }).getByText(literalSymbol, { exact: true })).toBeVisible();
    expect(await page.evaluate(() => (window as Window & { EXECUTABLE_NAME_RAN?: boolean }).EXECUTABLE_NAME_RAN)).toBeUndefined();
    await expect(structure.locator('script, img, a')).toHaveCount(0);
    if (width < 1000) {
      const scroll = structure.getByRole('region', { name: 'Executable sections', exact: true });
      await scroll.focus();
      await page.keyboard.press('ArrowRight');
      await expect.poll(() => scroll.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
    }
    await noPageOverflow(page);
  });
}

test('ordinary source files retain generic analysis without invented executable tables', async ({ page }) => {
  await page.getByLabel('File to inspect', { exact: true }).setInputFiles({ name: 'source.py', mimeType: 'text/plain', buffer: Buffer.from("print('hello')\n") });
  await page.getByRole('button', { name: 'Inspect file', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'File fingerprints', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Executable structure', exact: true })).toHaveCount(0);
});
