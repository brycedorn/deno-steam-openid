# deno-steam-openid

![deno_steam_openid module version](https://shield.deno.dev/x/deno_steam_openid)

A [Deno](https://deno.land) package to orchestrate
[OpenID](https://openid.net/what-is-openid/) authentication flow with
[Steam](https://store.steampowered.com/).

Borrows from [node-openid](https://github.com/havard/node-openid) and
[node-steam-openid](https://www.npmjs.com/package/node-steam-openid) with
modifications to support the Deno runtime. Note: not all OpenID functionality is
supported; only authentication logic required to support flow with Steam.

## Usage

OpenID flow confirmed to work with these frameworks:

- [Fresh](https://fresh.deno.dev/)
- [Oak](https://oakserver.github.io/oak/)

```typescript
import { SteamAuth } from 'https://deno.land/x/deno_steam_openid/mod.ts';

// Initialize
const steam = new SteamAuth({
  realm: Deno.env.get('DOMAIN'),
  returnUrl: `${Deno.env.get('DOMAIN')}/auth`,
  apiKey: Deno.env.get('API_KEY'),
});

// Redirect to Steam
const handler = async () {
  const redirectUrl = await steam.getRedirectUrl();
}

// Handle redirect from Steam
const otherHandler = async (request) {
  const user = await steam.authenticate(request);
}
```

## Example

There's a simple [Oak](https://deno.land/x/oak@v10.6.0) example in the
[example](https://github.com/brycedorn/deno-steam-openid/tree/main/example)
directory that demonstrates the flow. This assumes you have the latest version
of Deno [installed](https://deno.land/manual/getting_started/installation).

1. Get a [Steam API key](https://steamcommunity.com/dev/apikey)
1. Run `cp .env.example .env`
1. Replace `xxxxx` in new `.env` file with your API key
1. Run `deno task example`
1. Open [localhost:8000](http://localhost:8000) and log in to Steam to be
   redirected to a page with your user information

## Test

```bash
deno task test
```

## Format

```bash
deno task fmt
```
