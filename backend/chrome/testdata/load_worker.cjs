// Execute the shipped worker's actual side-effect imports in its VM fixture.
// Deriving this list from worker.js keeps new packaged dependencies visible to
// the Go/JS wire tests instead of silently testing an obsolete hand-copied list.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
module.exports = function loadWorker(context, root, fixtureExports = '') {
  const file = path.join(root, 'worker.js');
  const source = fs.readFileSync(file, 'utf8');
  const body = source.replace(/^import "\.\/([a-z0-9-]+\.js)";$/gm, (_, name) => {
    vm.runInContext(fs.readFileSync(path.join(root, name), 'utf8'), context, {filename: name});
    return '';
  });
  vm.runInContext(body + '\n' + fixtureExports, context, {filename: 'worker.js'});
};
