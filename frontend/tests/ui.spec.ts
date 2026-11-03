import { test, expect } from '@playwright/test';

test('search, evidence, persistent note, and real graph relationships work offline', async ({ page }) => {
  const errors: string[] = [];
  const remoteRequests: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => {
    if (!request.url().startsWith('http://127.0.0.1:8732/')) remoteRequests.push(request.url());
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Research overview', exact: true })).toBeVisible();
  await page.getByLabel('Search intelligence', { exact: true }).fill('CVE-2024-3094');
  await page.getByLabel('Search intelligence', { exact: true }).press('Enter');
  await expect(page.getByRole('heading', { name: 'Vulnerability intelligence', exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'CVE-2024-3094', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'XZ Utils supply-chain compromise', exact: true })).toBeVisible();
  await expect(page.getByText('10.0', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: 'Add research note', exact: true }).click();
  await page.getByLabel('Note title', { exact: true }).fill('Supply-chain evidence');
  await page.getByLabel('Note content', { exact: true }).fill('Investigating CVE-2024-3094. <script>window.UNTRUSTED_NOTE_EXECUTED = true</script>');
  await page.getByLabel('Source URLs', { exact: true }).fill('https://www.openwall.com/lists/oss-security/2024/03/29/4');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByText('Saved in the local database.', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('Supply-chain evidence');
  await expect(page.getByLabel('Note content', { exact: true })).toHaveValue(/CVE-2024-3094/);
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).UNTRUSTED_NOTE_EXECUTED)).toBeUndefined();
  await page.getByRole('navigation', { name: 'Main workspace' }).getByRole('link', { name: 'Knowledge graph', exact: true }).click();
  await page.getByLabel('Focus identifier', { exact: true }).fill('CVE-2024-3094');
  await page.getByRole('button', { name: 'Show relationships', exact: true }).click();
  await expect(page.getByRole('table', { name: 'Evidence relationships' }).getByText('documents', { exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Evidence relationships' }).getByText('Supply-chain evidence', { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
  expect(remoteRequests).toEqual([]);
});

test('exact dependency audit and read-only artifact inspection have usable results', async ({ page }) => {
  await page.goto('/#/lab');
  await expect(page.getByRole('heading', { name: 'Analysis lab', exact: true })).toBeVisible();
  await page.getByLabel('Dependency manifest', { exact: true }).fill('{"dependencies":{"lodash":"4.17.20"}}');
  await page.getByLabel('Send exact package coordinates to OSV', { exact: true }).check();
  await page.getByRole('button', { name: 'Audit dependencies', exact: true }).click();
  await expect(page.getByRole('link', { name: 'GHSA-35jh-r3h4-6jhm', exact: true })).toBeVisible();
  await page.getByLabel('File to inspect', { exact: true }).setInputFiles({ name: 'sample.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('MZ\0powershell https://example.org/test\0') });
  await page.getByRole('button', { name: 'Inspect file', exact: true }).click();
  await expect(page.getByText('PE/DOS executable header', { exact: true })).toBeVisible();
  await expect(page.getByText('Shell / command interpreter reference', { exact: true })).toBeVisible();
  await expect(page.getByText('No code executed', { exact: true })).toBeVisible();
});

test('larger artifact analysis surfaces entropy map, embedded segments, and UTF-16 strings without extraction', async ({ page }) => {
  await page.goto('/#/lab');
  await expect(page.getByText(/Up to 64 MiB/)).toBeVisible();
  const utf16 = Buffer.from('hidden-tunnel.example.net', 'utf16le');
  const buffer = Buffer.concat([
    Buffer.from('MZ\0\0 https://silent.example.org/drop CreateRemoteThread \x00'),
    Buffer.from('\x00'.repeat(500)), Buffer.from('PK\x03\x04\0\0\0\0'),
    Buffer.from('\x00'.repeat(500)), Buffer.from('%PDF-1.4\0\0'), utf16,
  ]);
  await page.getByLabel('File to inspect', { exact: true }).setInputFiles({ name: 'composite.bin', mimeType: 'application/octet-stream', buffer });
  await page.getByRole('button', { name: 'Inspect file', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Entropy map' })).toBeVisible();
  await expect(page.getByRole('img', { name: /Entropy map/ })).toBeVisible();
  await expect(page.getByRole('heading', { name: /Embedded segments/ })).toBeVisible();
  await expect(page.getByText('ZIP archive', { exact: true })).toBeVisible();
  await expect(page.getByText('PDF document', { exact: true })).toBeVisible();
  await expect(page.getByText(/located, never extracted/)).toBeVisible();
  await expect(page.getByRole('heading', { name: /UTF-16 strings/ })).toBeVisible();
  await page.getByText('UTF-16 strings found (1)').click();
  await expect(page.getByText('hidden-tunnel.example.net', { exact: true }).last()).toBeVisible();
  await expect(page.getByText('Whole file scanned')).toBeVisible();
});

test('source limits are visible and export contains local evidence', async ({ page }) => {
  await page.goto('/#/sources');
  await expect(page.getByRole('heading', { name: 'Public sources', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'CISA KEV', exact: true })).toBeVisible();
  await expect(page.getByText(/5 requests\/30 seconds/)).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('link', { name: 'Export research', exact: true }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^signal-atlas-.*\.json$/);
});

test('mobile layout, focusable navigation, and plain-text note rendering', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Research overview', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByRole('navigation', { name: 'Main workspace' }).getByRole('link', { name: 'Research library', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Research library', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'New note', exact: true }).click();
  await expect(page.getByLabel('Note title', { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByLabel('Note title', { exact: true }).focus();
  await expect(page.getByLabel('Note title', { exact: true })).toBeFocused();
});

test('successive note saves use the latest revision without a reload', async ({ page }) => {
  await page.goto('/#/research/new');
  await page.getByLabel('Note title', { exact: true }).fill('Iterative research');
  await page.getByLabel('Note content', { exact: true }).fill('First observation.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByText('Revision 1', { exact: true })).toBeVisible();
  await page.getByLabel('Note content', { exact: true }).fill('Second observation.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByText('Revision 2', { exact: true })).toBeVisible();
  await page.getByLabel('Note content', { exact: true }).fill('Third observation.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByText('Revision 3', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel('Note content', { exact: true })).toHaveValue('Third observation.');
});

test('internal navigation warns before discarding an unsaved note', async ({ page }) => {
  await page.goto('/#/research/new');
  await page.getByLabel('Note title', { exact: true }).fill('Unsaved research');
  let warned = false;
  page.once('dialog', async dialog => { warned = true; expect(dialog.message()).toMatch(/unsaved/i); await dialog.dismiss(); });
  await page.getByRole('navigation', { name: 'Main workspace' }).getByRole('link', { name: 'Analysis lab', exact: true }).click();
  await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('Unsaved research');
  expect(warned).toBe(true);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('navigation', { name: 'Main workspace' }).getByRole('link', { name: 'Analysis lab', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Analysis lab', exact: true })).toBeVisible();
});

test('starting another new note confirms before replacing the current draft', async ({ page }) => {
  await page.goto('/#/research/new');
  await page.getByLabel('Note title', { exact: true }).fill('Keep this draft');
  let warned = false;
  page.once('dialog', async dialog => { warned = true; await dialog.dismiss(); });
  await page.getByRole('button', { name: 'New note', exact: true }).click();
  await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('Keep this draft');
  expect(warned).toBe(true);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'New note', exact: true }).click();
  await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('');
});

test('browser back navigation can be cancelled without losing a note draft', async ({ page }) => {
  await page.goto('/#/lab');
  await page.getByRole('navigation', { name: 'Main workspace' }).getByRole('link', { name: 'Research library', exact: true }).click();
  await page.getByRole('button', { name: 'New note', exact: true }).click();
  await page.getByLabel('Note title', { exact: true }).fill('History-safe draft');
  let warned = false;
  page.once('dialog', async dialog => { warned = true; await dialog.dismiss(); });
  await page.goBack();
  await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('History-safe draft');
  await expect(page).toHaveURL(/#\/research\/new$/);
  expect(warned).toBe(true);
});

test('keyboard skip link keeps the current route and focuses the workspace', async ({ page }) => {
  await page.goto('/#/lab');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to research workspace', exact: true })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('main')).toBeFocused();
  await expect(page.getByRole('heading', { name: 'Analysis lab', exact: true })).toBeVisible();
});

test('deleted notes can be restored with their saved plain-text content', async ({ page }) => {
  await page.goto('/#/research/new');
  await page.getByLabel('Note title', { exact: true }).fill('Restorable evidence');
  await page.getByLabel('Note content', { exact: true }).fill('<script>window.RESTORED_NOTE_EXECUTED = true</script>');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByText('Revision 1', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Delete note', exact: true }).click();
  await expect(page.getByRole('link', { name: /^Restorable evidence/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Undo delete', exact: true }).click();
  await expect(page.getByLabel('Note title', { exact: true })).toHaveValue('Restorable evidence');
  await page.reload();
  await page.getByText('Read saved note as plain text', { exact: true }).click();
  await expect(page.locator('.note-reader .plain-text')).toHaveText('<script>window.RESTORED_NOTE_EXECUTED = true</script>');
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).RESTORED_NOTE_EXECUTED)).toBeUndefined();
});

test('audit without consent is not presented as clean and later reuses the cached query', async ({ page }) => {
  await page.goto('/#/lab');
  await page.getByLabel('Dependency manifest', { exact: true }).fill('{"dependencies":{"fresh-fixture-package":"1.0.0"}}');
  await page.getByRole('button', { name: 'Audit dependencies', exact: true }).click();
  await expect(page.getByText('Not checked', { exact: true })).toBeVisible();
  await expect(page.getByText('0 of 1 package versions checked', { exact: true })).toBeVisible();
  await page.getByLabel('Send exact package coordinates to OSV', { exact: true }).check();
  await page.getByRole('button', { name: 'Audit dependencies', exact: true }).click();
  await expect(page.getByRole('link', { name: 'GHSA-35jh-r3h4-6jhm', exact: true })).toBeVisible();
  await page.getByLabel('Send exact package coordinates to OSV', { exact: true }).uncheck();
  await page.getByRole('button', { name: 'Audit dependencies', exact: true }).click();
  await expect(page.getByText('Cached', { exact: true })).toBeVisible();
  await expect(page.getByText('1 of 1 package versions checked', { exact: true })).toBeVisible();
});

test('PCAP inspection shows decoded endpoints without starting a network capture', async ({ page }) => {
  const packet = Buffer.from('00000000000000000000000008004500001c0000000040110000c0000201080808083039003500080000', 'hex');
  const header = Buffer.from('d4c3b2a1020004000000000000000000ffff000001000000', 'hex');
  const frame = Buffer.alloc(16);
  frame.writeUInt32LE(1, 0); frame.writeUInt32LE(packet.length, 8); frame.writeUInt32LE(packet.length, 12);
  await page.goto('/#/lab');
  await page.getByLabel('File to inspect', { exact: true }).setInputFiles({ name: 'research.pcap', mimeType: 'application/octet-stream', buffer: Buffer.concat([header, frame, packet]) });
  await page.getByRole('button', { name: 'Inspect file', exact: true }).click();
  const table = page.getByRole('table', { name: 'Decoded network conversations', exact: true });
  await expect(table.getByText('192.0.2.1:12345', { exact: true })).toBeVisible();
  await expect(table.getByText('8.8.8.8:53', { exact: true })).toBeVisible();
  await expect(page.getByText('1 packets decoded', { exact: true })).toBeVisible();
  await expect(page.getByText('No code executed', { exact: true })).toBeVisible();
});

test('all workspace views reflow at narrow and zoom-equivalent widths without remote assets', async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  const errors: string[] = [];
  const remoteRequests: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => {
    if (new URL(request.url()).origin !== 'http://127.0.0.1:8732') remoteRequests.push(request.url());
  });
  const views = [
    ['overview', 'Research overview'], ['intelligence', 'Vulnerability intelligence'],
    ['research', 'Research library'], ['graph', 'Knowledge graph'],
    ['lab', 'Analysis lab'], ['sources', 'Public sources'],
  ];
  for (const width of [320, 390, 720, 1440]) {
    await page.setViewportSize({ width, height: width <= 390 ? 844 : 1000 });
    for (const [route, heading] of views) {
      await page.goto(`/#/${route}`);
      await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
      await expect(page.locator('main .loading')).toHaveCount(0);
      const dimensions = await page.evaluate(() => ({ viewport: innerWidth, content: document.documentElement.scrollWidth }));
      expect(dimensions.content, `${route} overflows at ${width}px`).toBeLessThanOrEqual(dimensions.viewport);
      if (width === 390 || width === 1440) {
        await page.screenshot({ path: testInfo.outputPath(`${route}-${width === 390 ? 'mobile' : 'desktop'}.png`) });
      }
    }
  }
  expect(errors).toEqual([]);
  expect(remoteRequests).toEqual([]);
});

test('a conflicting LAN edit cannot overwrite a newer note or erase the local draft', async ({ page }) => {
  await page.goto('/#/research/new');
  await page.getByLabel('Note title', { exact: true }).fill('Shared research evidence');
  await page.getByLabel('Note content', { exact: true }).fill('Initial shared observation.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByText('Revision 1', { exact: true })).toBeVisible();
  const noteId = new URL(page.url()).hash.split('/').at(-1)!;
  const newer = await page.request.put(`/api/notes/${noteId}`, { data: { revision: 1, body: 'Newer observation from another client.' } });
  expect(newer.ok()).toBe(true);
  await page.getByLabel('Note content', { exact: true }).fill('My unsaved competing observation.');
  await page.getByRole('button', { name: 'Save note', exact: true }).click();
  await expect(page.getByRole('alert').getByText(/This note changed/)).toBeVisible();
  await expect(page.getByLabel('Note content', { exact: true })).toHaveValue('My unsaved competing observation.');
  const stored = await page.request.get(`/api/notes/${noteId}`);
  expect((await stored.json()).body).toBe('Newer observation from another client.');
});

test('metric explanations stay inside valid definition-list entries', async ({ page }) => {
  await page.goto('/#/overview');
  await expect(page.locator('.metrics-strip')).toBeVisible();
  await expect(page.locator('main dl > div > :not(dt):not(dd)')).toHaveCount(0);
  await page.goto('/#/vulnerability/CVE-2024-3094');
  await expect(page.locator('.signal-strip')).toBeVisible();
  await expect(page.locator('main dl > div > :not(dt):not(dd)')).toHaveCount(0);
});

test('empty result workspaces keep a logical heading hierarchy', async ({ page }) => {
  await page.goto('/#/intelligence');
  await page.getByLabel('Search intelligence', { exact: true }).fill('no-fixture-can-match-this');
  await page.getByLabel('Search intelligence', { exact: true }).press('Enter');
  await expect(page.getByRole('heading', { name: 'No cached records match', level: 2 })).toBeVisible();
  await page.goto('/#/graph?focus=CVE-9999-9999');
  await expect(page.getByRole('heading', { name: 'No cached relationships to show', level: 2 })).toBeVisible();
  await page.goto('/#/research');
  await expect(page.getByRole('heading', { name: 'A place for the reasoning behind the record', level: 2 })).toBeVisible();
});

test('a malformed encoded identifier cannot crash the workspace route', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/#/vulnerability/%');
  await page.waitForLoadState('networkidle');
  expect(errors).toEqual([]);
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Main workspace' })).toBeVisible();
});

test('graph relationship lines remain distinguishable against the patterned canvas', async ({ page }) => {
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await page.goto('/#/graph?focus=CVE-2024-3094');
    await expect(page.locator('.graph-node').first()).toBeVisible();
    expect(await page.locator('.graph-edge').count()).toBeGreaterThan(0);
    const ratios = await page.locator('.graph-edge').evaluateAll(edges => {
      const luminance = (color: string) => color.match(/[\d.]+/g)!.slice(0, 3).map(Number).map(value => value / 255)
        .map(value => value <= 0.04045 ? value / 12.92 : ((value + .055) / 1.055) ** 2.4)
        .reduce((sum, value, index) => sum + value * [.2126, .7152, .0722][index], 0);
      const backgrounds = [getComputedStyle(document.querySelector('.graph-visual')!).backgroundColor, getComputedStyle(document.querySelector('#graph-grid circle')!).fill];
      return edges.flatMap(edge => backgrounds.map(background => {
        const foreground = luminance(getComputedStyle(edge).stroke); const behind = luminance(background);
        return (Math.max(foreground, behind) + .05) / (Math.min(foreground, behind) + .05);
      }));
    });
    expect(Math.min(...ratios), `Relationship line contrast at ${width}px`).toBeGreaterThanOrEqual(3);
  }
});
