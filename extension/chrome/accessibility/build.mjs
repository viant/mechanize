import {build} from 'esbuild';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const directory=fileURLToPath(new URL('../',import.meta.url));
await build({entryPoints:[directory+'accessibility/provider.mjs'],outfile:directory+'accessibility-provider.js',format:'iife',globalName:'MechanizeAccessibility',bundle:true,minify:true,legalComments:'inline',banner:{js:'// Generated from pinned dom-accessibility-api@0.7.1 (MIT); see accessibility/LICENSE.dom-accessibility-api.\n// Rebuild: npm run build-accessibility'}});
await writeFile(directory+'accessibility/LICENSE.dom-accessibility-api',await readFile(directory+'node_modules/dom-accessibility-api/LICENSE.md'));
