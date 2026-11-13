import {createInterface} from 'node:readline';
const lines = createInterface({input: process.stdin});
lines.on('line', line => {
  const request = JSON.parse(line);
  if (request.method === 'hang') return;
  if (request.method === 'exit') {process.exit(1); return;}
  const reply = request.method === 'error'
    ? {id: request.id, error: {code: 'deadline', message: 'Deadline reached', outcome: 'unknown'}}
    : {id: request.id, result: {session: request.session}};
  setTimeout(() => process.stdout.write(JSON.stringify(reply) + '\n'), request.session === 'slow' ? 20 : 0);
});
