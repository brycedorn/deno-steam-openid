import { Application, Router } from 'https://deno.land/x/oak@v10.6.0/mod.ts';
import 'https://deno.land/x/dotenv/load.ts';

import SteamAuth from '../mod.ts';

const app = new Application();
const router = new Router();
const hostname = 'localhost';
const authPath = '/auth';
const port = 8000;

const steam = new SteamAuth({
  realm: `http://${hostname}:${port}`,
  returnUrl: `http://${hostname}:${port}${authPath}`,
  apiKey: Deno.env.get('API_KEY'),
});

router.get('/', async (ctx) => {
  const redirectUrl = await steam.getRedirectUrl();
  ctx.response.redirect(redirectUrl);
});

router.get(authPath, async (ctx) => {
  try {
    const user = await steam.authenticate(ctx);
    ctx.response.type = 'application/json';
    ctx.response.body = user;
  } catch (e) {
    ctx.response.body = `Error: ${e}`;
  }
});

app.use(router.routes());

app.addEventListener('listen', ({ hostname, port }) => {
  console.log(`Listening on http://${hostname}:${port}`);
});

await app.listen({ port });
