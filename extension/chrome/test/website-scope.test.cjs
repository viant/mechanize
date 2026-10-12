const {test} = require('node:test');
const assert = require('node:assert/strict');
const protocol = require('../protocol.js');

test('all websites admits new HTTP and HTTPS sites without an origin list', () => {
  const enrollment = {allWebsites:true, origins:[]};
  for (const url of ['https://one.example.test/a', 'https://other.example.test/b', 'http://ordinary.example.test/c', 'http://localhost:1234/']) {
    assert.equal(protocol.websiteAllowed(url,enrollment),true,url);
  }
});
test('all websites excludes browser internals, files, embedded credentials and contradictory scope', () => {
  for (const url of ['file:///private/fixture', 'chrome://settings', 'chrome-extension://fixture/options.html',
                     'data:text/html,x', 'javascript:alert(1)', 'blob:https://one.example.test/x',
                     'https://fixture-user:fixture-password@one.example.test/a']) {
    assert.equal(protocol.websiteAllowed(url,{allWebsites:true,origins:[]}),false);
  }
  for (const enrollment of [{allWebsites:'true',origins:[]},{allWebsites:true,origins:['https://one.example.test']},
                            {allWebsites:true},{origins:[]},{origins:['https://one.example.test/']}]) {
    assert.equal(protocol.websiteScopeValid(enrollment),false);
    assert.equal(protocol.websiteAllowed('https://one.example.test',enrollment),false);
  }
});
test('legacy selected website scope remains narrow', () => {
  const enrollment={origins:['https://one.example.test','http://127.0.0.1:1234']};
  assert.equal(protocol.websiteAllowed('https://one.example.test/a',enrollment),true);
  assert.equal(protocol.websiteAllowed('http://127.0.0.1:1234/a',enrollment),true);
  assert.equal(protocol.websiteAllowed('https://other.example.test',enrollment),false);
  assert.equal(protocol.websiteAllowed('https://fixture-user:fixture-password@one.example.test',enrollment),false);
});
