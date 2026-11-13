// Receives validated, resolved Mechanize steps over private child-process IPC.
// This adapter owns container pages; it does not impersonate the desktop broker.
export const actions = ['browser.openOrigin', 'browser.navigate', 'browser.activate',
  'element.press', 'element.fill', 'element.check', 'element.uncheck',
  'element.select', 'element.pressKey', 'element.focus', 'element.read', 'expect'];

// Go's tagged Value uses omitempty for zero values. The kind distinguishes an
// empty string from an absent argument; preserve that distinction at the IPC seam.
function stringValue(value) {
  if (value?.kind !== 'string') throw Error('Resolved string value required');
  return value.string ?? '';
}

function locator(root, target) {
  if (target.ancestor) root = locator(root, target.ancestor);
  const l = target.locator;
  if (!l) throw Error('Element locator required');
  const value = stringValue(l.value);
  let result;
  switch (l.strategy) {
    case 'role': result = root.getByRole(value, {name: l.name ? stringValue(l.name) : undefined, exact: l.exact}); break;
    case 'text': result = root.getByText(value, {exact: l.exact}); break;
    case 'label': result = root.getByLabel(value, {exact: l.exact}); break;
    case 'id': case 'testId': {
      const attribute = l.strategy === 'id' ? 'id' : 'data-testid';
      result = root.locator(`[${attribute}${l.exact ? '=' : '*='}${JSON.stringify(value)}]`);
      break;
    }
    default: throw Error('Unsupported locator strategy');
  }
  if (target.cardinality === 'nth') result = result.nth(target.index);
  return result;
}

async function read(target, attribute) {
  switch (attribute) {
    case 'text': return target.textContent();
    case 'value': return target.inputValue();
    case 'checked': return target.isChecked();
    case 'enabled': return target.isEnabled();
    case 'visible': return target.isVisible();
    default: throw Error('Unsupported read attribute');
  }
}

export async function executeStep(page, step) {
  const state = {dispatched: false};
  try { return await execute(page, step, state); }
  catch (cause) {
    const error = new Error('Browser step failed', {cause});
    error.code = cause.code ?? (cause.name === 'TimeoutError' ? 'deadline' : 'browserStepFailed');
    error.outcome = state.dispatched ? 'unknown' : 'notDispatched';
    throw error;
  }
}

async function execute(page, step, state) {
  if (!actions.includes(step.action) || step.target.surface.kind !== 'web' ||
      Object.keys(step.target.scope?.frame ?? {}).length || Object.keys(step.target.scope?.window ?? {}).length) {
    throw Error('Unsupported browser step');
  }
  const timeout = step.timeoutMs;
  if (!Number.isSafeInteger(timeout) || timeout <= 0) throw Error('Bounded timeout required');
  page.setDefaultTimeout(timeout);
  const surface = step.target.surface;
  if (surface.tabId) throw Error('Explicit tab identity unavailable in container executor');
  if (step.action !== 'browser.openOrigin') {
    if (new URL(page.url()).origin !== surface.origin) throw Error('Session tab origin mismatch');
    if (surface.title && await page.title() !== surface.title) throw Error('Session tab title mismatch');
  }
  if (step.action === 'browser.openOrigin' || step.action === 'browser.navigate') {
    const url = step.action === 'browser.openOrigin' ? surface.origin : stringValue(step.arguments.url);
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) throw Error('Invalid navigation URL');
    state.dispatched = true;
    await page.goto(url, {timeout, waitUntil: 'domcontentloaded'});
    return page.url();
  }
  if (step.action === 'browser.activate') {state.dispatched = true; await page.bringToFront(); return null;}
  const target = locator(page, step.target);
  if (step.action === 'expect') {
    const assertion = step.assertion;
    const deadline = Date.now() + timeout;
    const expected = assertion.expected;
    while (true) {
      let matches = false;
      if (await target.count() === 1) {
        switch (assertion.matcher) {
          case 'toBeVisible': matches = await target.isVisible(); break;
          case 'toBeEnabled': matches = await target.isEnabled(); break;
          case 'toBeChecked': matches = await target.isChecked(); break;
          case 'toHaveText': matches = await target.textContent() === stringValue(expected); break;
          case 'toHaveValue': matches = await target.inputValue() === stringValue(expected); break;
          default: throw Error('Unsupported assertion');
        }
      } else if (await target.count() > 1) throw Error('Ambiguous assertion target');
      if (assertion.not ? !matches : matches) return true;
      if (Date.now() >= deadline) throw Object.assign(Error('Assertion deadline exceeded'), {code:'deadline'});
      await page.waitForTimeout(Math.min(50, deadline - Date.now()));
    }
  }
  if (step.target.cardinality === 'all') {
    if (step.action !== 'element.read') throw Error('Plural mutations unsupported');
    const count = await target.count();
    if (count > step.target.limit) throw Error('Read result exceeds declared limit');
    const values = [];
    for (let i = 0; i < count; i++) values.push(await read(target.nth(i), stringValue(step.arguments.attribute)));
    return values;
  }
  await target.waitFor({state: 'attached', timeout});
  if (await target.count() !== 1) throw Error('Strict target cardinality required');
  state.dispatched = step.action !== 'element.read';
  switch (step.action) {
    case 'element.press': await target.click({timeout}); break;
    case 'element.fill': await target.fill(stringValue(step.arguments.value), {timeout}); break;
    case 'element.check': await target.check({timeout}); break;
    case 'element.uncheck': await target.uncheck({timeout}); break;
    case 'element.select': await target.selectOption(stringValue(step.arguments.value), {timeout}); break;
    case 'element.pressKey': await target.press(stringValue(step.arguments.key), {timeout}); break;
    case 'element.focus': await target.focus({timeout}); break;
    case 'element.read': return read(target, stringValue(step.arguments.attribute));
  }
  return null;
}
