import { RelyingParty } from './openid.ts';

const STEAM_OPENID_URL = 'https://steamcommunity.com/openid';
const GET_PLAYER_SUMMARY =
  'https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/';

export default class SteamAuth {
  constructor({ realm, returnUrl, apiKey }) {
    if (!realm || !returnUrl || !apiKey) {
      throw new Error(
        'Missing realm, returnURL or apiKey required parameter(s).',
      );
    }

    this.apiKey = apiKey;
    this.relyingParty = new RelyingParty(returnUrl, realm, true, true, []);
  }

  getRedirectUrl() {
    return new Promise((resolve, reject) => {
      this.relyingParty.authenticate(
        STEAM_OPENID_URL,
        false,
        (error, authUrl) => {
          if (error) {
            return reject('Authentication failed: ' + JSON.stringify(error));
          } else if (!authUrl) {
            return reject('Authentication failed.');
          }

          resolve(authUrl);
        },
      );
    });
  }

  async fetchIdentifier(steamOpenId) {
    const steamId = steamOpenId.replace(`${STEAM_OPENID_URL}/id/`, '');

    try {
      const response = await fetch(
        `${GET_PLAYER_SUMMARY}?key=${this.apiKey}&steamids=${steamId}`,
      );
      const data = await response.json();
      const players = data.response.players;

      if (players && players.length > 0) {
        return players[0];
      } else {
        throw new Error('No players found for the given SteamID.');
      }
    } catch (error) {
      throw new Error('Steam server error: ' + error.message);
    }
  }

  authenticate(req) {
    return new Promise((resolve, reject) => {
      this.relyingParty.verifyAssertion(req, async (error, result) => {
        if (error) {
          return reject(error.message);
        } else if (!result || !result.authenticated) {
          return reject('Failed to authenticate user.');
        } else if (
          !/^https?:\/\/steamcommunity\.com\/openid\/id\/\d+$/.test(
            result.claimedIdentifier,
          )
        ) {
          return reject('Claimed identity is not valid.');
        }

        try {
          const user = await this.fetchIdentifier(result.claimedIdentifier);
          return resolve(user);
        } catch (error) {
          reject(error);
        }
      });
    });
  }
}
