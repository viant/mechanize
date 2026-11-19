// Synthetic OAuth access tokens for container smoke tests. Never uses real credentials.
import {generateKeyPairSync, sign} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';

export async function browserOAuthFixture(directory) {
  const {publicKey, privateKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
  await writeFile(join(directory, 'oauth-public.pem'), publicKey.export({type:'spki',format:'pem'}), {mode:0o600});
  const issuer = 'https://issuer.example';
  const audience = 'https://browser.example/mcp';
  const tokens = new Map();
  return {
    config: {
      keys: {RSA: [{URL:'/run/browser-secrets/oauth-public.pem'}]},
      identityPolicy: {issuer, algorithms:['RS256'], requiredScopes:['browser:use']},
    },
    authorization(subject = 'fixture-user') {
      if (!tokens.has(subject)) {
        const header = Buffer.from(JSON.stringify({alg:'RS256',typ:'at+jwt'})).toString('base64url');
        const payload = Buffer.from(JSON.stringify({iss:issuer,aud:audience,sub:subject,client_id:'browser-fixture',scope:'browser:use',exp:Math.floor(Date.now()/1000)+3600})).toString('base64url');
        const input = `${header}.${payload}`;
        tokens.set(subject, `Bearer ${input}.${sign('RSA-SHA256',Buffer.from(input),privateKey).toString('base64url')}`);
      }
      return {Authorization:tokens.get(subject)};
    },
  };
}
