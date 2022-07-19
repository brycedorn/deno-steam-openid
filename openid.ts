import url from 'https://deno.land/std@0.148.0/node/url.ts';
import { parse } from 'https://deno.land/x/xml@2.0.4/mod.ts';

const _discoveries = {};
const _nonces = {};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

const _isDef = function (e) {
  return e !== undefined;
};

const _buildUrl = function (theUrl, params) {
  theUrl = url.parse(theUrl, true);
  delete theUrl['search'];
  if (params) {
    if (!theUrl.query) {
      theUrl.query = params;
    } else {
      for (const key in params) {
        if (hasOwnProperty(params, key)) {
          theUrl.query[key] = params[key];
        }
      }
    }
  }

  return url.format(theUrl);
};

const _normalizeIdentifier = function (identifier) {
  identifier = identifier.replace(/^\s+|\s+$/g, '');
  if (!identifier) {
    return null;
  }
  if (identifier.indexOf('xri://') === 0) {
    identifier = identifier.substring(6);
  }

  if (/^[(=@\+\$!]/.test(identifier)) {
    return identifier;
  }

  if (identifier.indexOf('http') === 0) {
    return identifier;
  }
  return 'http://' + identifier;
};

function _parseXrds(xrdsUrl, xrdsData) {
  const service = parse(xrdsData)['xrds:XRDS'].XRD.Service;

  const provider = {
    endpoint: service.URI,
  };

  if (/https?:\/\/xri./.test(xrdsUrl)) {
    provider.claimedIdentifier = service.id;
  }

  const type = service.Type;
  if (type == 'http://specs.openid.net/auth/2.0/signon') {
    provider.version = 'http://specs.openid.net/auth/2.0';
    provider.localIdentifier = service.id;
  } else if (type == 'http://specs.openid.net/auth/2.0/server') {
    provider.version = 'http://specs.openid.net/auth/2.0';
  } else if (
    type == 'http://openid.net/signon/1.0' ||
    type == 'http://openid.net/signon/1.1'
  ) {
    provider.version = type;
    provider.localIdentifier = service.delegate;
  }

  return [provider];
}

const _resolveXri = async function (xriUrl, callback, hops) {
  if (!hops) {
    hops = 1;
  } else if (hops >= 5) {
    return callback(null);
  }

  const response = await fetch(xriUrl);
  const { headers } = response;
  const statusCode = response.status;
  const data = await response.text();
  if (statusCode != 200) {
    return callback(null);
  }

  if (data != null) {
    const contentType = headers.get('content-type');
    // text/xml is not compliant, but some hosting providers refuse header
    // changes, so text/xml is encountered
    if (
      contentType &&
      (contentType.indexOf('application/xrds+xml') === 0 ||
        contentType.indexOf('text/xml') === 0)
    ) {
      return callback(_parseXrds(xriUrl, data));
    } else {
      return callback({ message: 'Unsupported content type' });
    }
  } else {
    return callback({ message: 'Error fetching XRI' });
  }
};

const _requestAuthentication = function (
  provider,
  assoc_handle,
  returnUrl,
  realm,
  immediate,
  extensions,
  callback,
) {
  const params = {
    'openid.mode': immediate ? 'checkid_immediate' : 'checkid_setup',
  };

  if (provider.version.indexOf('2.0') !== -1) {
    params['openid.ns'] = 'http://specs.openid.net/auth/2.0';
  }

  for (const i in extensions) {
    if (!hasOwnProperty(extensions, i)) {
      continue;
    }

    const extension = extensions[i];
    for (const key in extension.requestParams) {
      if (!hasOwnProperty(extension.requestParams, key)) continue;
      params[key] = extension.requestParams[key];
    }
  }

  if (provider.version.indexOf('2.0') !== -1) {
    params['openid.claimed_id'] =
      params['openid.identity'] =
        'http://specs.openid.net/auth/2.0/identifier_select';
  } else {
    return callback({
      message:
        'OpenID 1.0/1.1 provider cannot be used without a claimed identifier',
    });
  }

  if (assoc_handle) {
    params['openid.assoc_handle'] = assoc_handle;
  }

  if (returnUrl) {
    params['openid.return_to'] = returnUrl;
  }

  if (realm) {
    if (provider.version.indexOf('2.0') !== -1) {
      params['openid.realm'] = realm;
    } else {
      params['openid.trust_root'] = realm;
    }
  } else if (!returnUrl) {
    return callback({ message: 'No return URL or realm specified' });
  }

  callback(null, _buildUrl(provider.endpoint, params));
};

const _verifyReturnUrl = function (assertionUrl, originalReturnUrl) {
  const params = new URLSearchParams(assertionUrl.search);
  let receivedReturnUrl = params.get('openid.return_to');
  if (!_isDef(receivedReturnUrl)) {
    return false;
  }

  receivedReturnUrl = url.parse(receivedReturnUrl, true);
  if (!receivedReturnUrl) {
    return false;
  }
  originalReturnUrl = url.parse(originalReturnUrl, true);
  if (!originalReturnUrl) {
    return false;
  }

  if (
    originalReturnUrl.protocol !== receivedReturnUrl.protocol || // Verify scheme against original return URL
    originalReturnUrl.host !== receivedReturnUrl.host || // Verify authority against original return URL
    originalReturnUrl.pathname !== receivedReturnUrl.pathname
  ) { // Verify path against current request URL
    return false;
  }

  // Any query parameters that are present in the "openid.return_to" URL MUST also be present
  // with the same values in the URL of the HTTP request the RP received
  for (const param in receivedReturnUrl.query) {
    if (
      hasOwnProperty(receivedReturnUrl.query, param) &&
      receivedReturnUrl.query[param] !== assertionUrl.query[param]
    ) {
      return false;
    }
  }

  return true;
};

const _getAssertionError = function (params) {
  if (!_isDef(params)) {
    return 'Assertion request is malformed';
  } else if (params['openid.mode'] == 'error') {
    return params['openid.error'];
  } else if (params['openid.mode'] == 'cancel') {
    return 'Authentication cancelled';
  }

  return null;
};

const _invalidateAssociationHandleIfRequested = function (params) {
  if (
    params['is_valid'] == 'true' && _isDef(params['openid.invalidate_handle'])
  ) {
    if (!openid.removeAssociation(params['openid.invalidate_handle'])) {
      return false;
    }
  }

  return true;
};

const _checkSignatureUsingProvider = async function (
  params,
  provider,
  callback,
) {
  const requestParams = {
    'openid.mode': 'check_authentication',
  };
  for (const [key, value] of params) {
    if (key != 'openid.mode') {
      requestParams[key] = value;
    }
  }

  const url = _isDef(params.get('openid.ns'))
    ? (params.get('openid.op_endpoint') || provider.endpoint)
    : provider.endpoint;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(requestParams),
  });

  if (response.status != 200) {
    return callback(
      { message: 'Invalid assertion response from provider' },
      { authenticated: false },
    );
  } else {
    if (response.ok) {
      return callback(null, {
        authenticated: true,
        claimedIdentifier: provider.version.indexOf('2.0') !== -1
          ? params.get('openid.claimed_id')
          : params.get('openid.identity'),
      });
    } else {
      return callback({ message: 'Invalid signature' }, {
        authenticated: false,
      });
    }
  }
};

const _getCanonicalClaimedIdentifier = function (claimedIdentifier) {
  if (!claimedIdentifier) {
    return claimedIdentifier;
  }

  const index = claimedIdentifier.indexOf('#');
  if (index !== -1) {
    return claimedIdentifier.substring(0, index);
  }

  return claimedIdentifier;
};

const _checkNonce = function (params) {
  if (!_isDef(params.get('openid.ns'))) {
    return true; // OpenID 1.1 has no nonce
  }
  if (!_isDef(params.get('openid.response_nonce'))) {
    return false;
  }

  const nonce = params.get('openid.response_nonce');
  const timestampEnd = nonce.indexOf('Z');
  if (timestampEnd == -1) {
    return false;
  }

  // Check for valid timestamp in nonce
  const timestamp = new Date(Date.parse(nonce.substring(0, timestampEnd + 1)));
  if (
    Object.prototype.toString.call(timestamp) !== '[object Date]' ||
    isNaN(timestamp)
  ) {
    return false;
  }

  // Remove old nonces from our store (nonces that are more skewed than 5 minutes)
  _removeOldNonces();

  // Check if nonce is skewed by more than 5 minutes
  if (Math.abs(new Date().getTime() - timestamp.getTime()) > 300000) {
    return false;
  }

  // Check if nonce is replayed
  if (_isDef(_nonces[nonce])) {
    return false;
  }

  // Store the nonce
  _nonces[nonce] = timestamp;
  return true;
};

const _removeOldNonces = function () {
  for (const nonce in _nonces) {
    if (
      hasOwnProperty(_nonces, nonce) &&
      Math.abs(new Date().getTime() - _nonces[nonce].getTime()) > 300000
    ) {
      delete _nonces[nonce];
    }
  }
};

const _verifyAssertionAgainstProviders = function (
  providers,
  params,
  stateless,
  extensions,
  callback,
) {
  for (let i = 0; i < providers.length; i++) {
    const provider = providers[i];
    if (
      !!params.get('openid.ns') &&
      (!provider.version ||
        provider.version.indexOf(params.get('openid.ns')) !== 0)
    ) {
      continue;
    }

    if (!!provider.version && provider.version.indexOf('2.0') !== -1) {
      const endpoint = params.get('openid.op_endpoint');
      if (provider.endpoint != endpoint) {
        continue;
      }
      if (provider.claimedIdentifier) {
        const claimedIdentifier = _getCanonicalClaimedIdentifier(
          params.get('openid.claimed_id'),
        );
        if (provider.claimedIdentifier != claimedIdentifier) {
          return callback({
            message:
              'Claimed identifier in assertion response does not match discovered claimed identifier',
          });
        }
      }
    }

    if (
      !!provider.localIdentifier &&
      provider.localIdentifier != params['openid.identity']
    ) {
      return callback({
        message:
          'Identity in assertion response does not match discovered local identifier',
      });
    }

    return _checkSignature(
      params,
      provider,
      stateless,
      function (error, result) {
        if (error) {
          return callback(error);
        }
        if (extensions && result.authenticated) {
          for (const ext in extensions) {
            if (!hasOwnProperty(extensions, ext)) {
              continue;
            }
            const instance = extensions[ext];
            instance.fillResult(params, result);
          }
        }

        return callback(null, result);
      },
    );
  }

  callback({
    message:
      'No valid providers were discovered for the asserted claimed identifier',
  });
};

const _checkSignature = function (params, provider, _stateless, callback) {
  if (
    !_isDef(params.get('openid.signed')) ||
    !_isDef(params.get('openid.sig'))
  ) {
    return callback({ message: 'No signature in response' }, {
      authenticated: false,
    });
  }

  _checkSignatureUsingProvider(params, provider, callback);
};

export class OpenId {
  verifyAssertion = function (
    requestOrUrl,
    originalReturnUrl,
    callback,
    stateless,
    extensions,
    strict,
  ) {
    let assertionUrl;

    if (requestOrUrl?.request?.url) {
      assertionUrl = requestOrUrl.request.url;
    } else if (requestOrUrl?.url) {
      assertionUrl = url.parse(requestOrUrl.url);
    }

    const params = new URLSearchParams(assertionUrl.search);

    if (!_verifyReturnUrl(assertionUrl, originalReturnUrl)) {
      return callback({ message: 'Invalid return URL' });
    }

    return this._verifyAssertionData(
      params,
      callback,
      stateless,
      extensions,
      strict,
    );
  };

  authenticate = function (
    identifier,
    returnUrl,
    realm,
    immediate,
    stateless,
    callback,
    extensions,
    strict,
  ) {
    this.discover(identifier, strict, function (error, providers) {
      if (error) {
        return callback(error);
      }
      if (!providers || providers.length === 0) {
        return callback({
          message: 'No providers found for the given identifier',
        }, null);
      }

      let providerIndex = -1;

      (function chooseProvider(error, authUrl) {
        if (!error && authUrl) {
          const provider = providers[providerIndex];

          if (provider.claimedIdentifier) {
            const useLocalIdentifierAsKey =
              provider.version.indexOf('2.0') === -1 &&
              provider.localIdentifier &&
              provider.claimedIdentifier != provider.localIdentifier;

            return openid.saveDiscoveredInformation(
              useLocalIdentifierAsKey
                ? provider.localIdentifier
                : provider.claimedIdentifier,
              provider,
              function (error) {
                if (error) {
                  return callback(error);
                }
                return callback(null, authUrl);
              },
            );
          } else if (provider.version.indexOf('2.0') !== -1) {
            return callback(null, authUrl);
          } else {
            chooseProvider({
              message:
                'OpenID 1.0/1.1 provider cannot be used without a claimed identifier',
            });
          }
        }
        if (++providerIndex >= providers.length) {
          return callback({
            message: 'No usable providers found for the given identifier',
          }, null);
        }

        const currentProvider = providers[providerIndex];
        if (stateless) {
          _requestAuthentication(
            currentProvider,
            null,
            returnUrl,
            realm,
            immediate,
            extensions || {},
            chooseProvider,
          );
        } else {
          openid.associate(currentProvider, function (error, answer) {
            if (error || !answer || answer.error) {
              chooseProvider(error || answer.error, null);
            } else {
              _requestAuthentication(
                currentProvider,
                answer.assoc_handle,
                returnUrl,
                realm,
                immediate,
                extensions || {},
                chooseProvider,
              );
            }
          });
        }
      })();
    });
  };

  discover = function (identifier, _strict, callback) {
    identifier = _normalizeIdentifier(identifier);
    if (!identifier) {
      return callback({ message: 'Invalid identifier' }, null);
    }
    if (identifier.indexOf('http') !== 0) {
      // XRDS
      identifier = 'https://xri.net/' + identifier +
        '?_xrd_r=application/xrds%2Bxml';
    }

    // Try XRDS/Yadis discovery
    _resolveXri(identifier, function (providers) {
      // Add claimed identifier to providers with local identifiers
      // and OpenID 1.0/1.1 providers to ensure correct resolution
      // of identities and services
      for (let i = 0, len = providers.length; i < len; i++) {
        const provider = providers[i];
        if (
          !provider.claimedIdentifier &&
          (provider.localIdentifier || provider.version.indexOf('2.0') === -1)
        ) {
          provider.claimedIdentifier = identifier;
        }
      }
      callback(null, providers);
    });
  };

  _verifyAssertionData = function (
    params,
    callback,
    stateless,
    extensions,
    strict,
  ) {
    const assertionError = _getAssertionError(params);
    if (assertionError) {
      return callback({ message: assertionError }, { authenticated: false });
    }

    if (!_invalidateAssociationHandleIfRequested(params)) {
      return callback({ message: 'Unable to invalidate association handle' });
    }

    if (!_checkNonce(params)) {
      return callback({ message: 'Invalid or replayed nonce' });
    }

    this._verifyDiscoveredInformation(
      this,
      params,
      stateless,
      extensions,
      strict,
      function (error, result) {
        return callback(error, result);
      },
    );
  };

  _verifyDiscoveredInformation = function (
    self,
    params,
    stateless,
    extensions,
    strict,
    callback,
  ) {
    let claimedIdentifier = params.get('openid.claimed_id');
    let useLocalIdentifierAsKey = false;
    if (!_isDef(claimedIdentifier)) {
      if (!_isDef(params.get('openid.ns'))) {
        // OpenID 1.0/1.1 response without a claimed identifier
        // We need to load discovered information using the
        // local identifier
        useLocalIdentifierAsKey = true;
      } else {
        // OpenID 2.0+:
        // If there is no claimed identifier, then the
        // assertion is not about an identity
        return callback(null, { authenticated: false });
      }
    }

    if (useLocalIdentifierAsKey) {
      claimedIdentifier = params.get('openid.identity');
    }

    claimedIdentifier = _getCanonicalClaimedIdentifier(claimedIdentifier);
    this.loadDiscoveredInformation(
      claimedIdentifier,
      function (error, provider) {
        if (error) {
          return callback({
            message:
              'An error occured when loading previously discovered information about the claimed identifier',
          });
        }

        if (provider) {
          return _verifyAssertionAgainstProviders(
            [provider],
            params,
            stateless,
            extensions,
            callback,
          );
        } else if (useLocalIdentifierAsKey) {
          return callback({
            message:
              'OpenID 1.0/1.1 response received, but no information has been discovered about the provider. It is likely that this is a fraudulent authentication response.',
          });
        }

        self.discover(claimedIdentifier, strict, function (error, providers) {
          if (error) {
            return callback(error);
          }
          if (!providers || !providers.length) {
            return callback({
              message:
                'No OpenID provider was discovered for the asserted claimed identifier',
            });
          }

          _verifyAssertionAgainstProviders(
            providers,
            params,
            stateless,
            extensions,
            callback,
          );
        });
      },
    );
  };

  saveDiscoveredInformation = function (key, provider, callback) {
    _discoveries[key] = provider;
    return callback(null);
  };

  loadDiscoveredInformation = function (key, callback) {
    if (!_isDef(_discoveries[key])) {
      return callback(null, null);
    }

    return callback(null, _discoveries[key]);
  };
}

export class RelyingParty {
  constructor(returnUrl, realm, stateless, strict, extensions) {
    this.returnUrl = returnUrl;
    this.realm = realm || null;
    this.stateless = stateless;
    this.strict = strict;
    this.extensions = extensions;

    this.openId = new OpenId();
  }

  authenticate = function (identifier, immediate, callback) {
    return this.openId.authenticate(
      identifier,
      this.returnUrl,
      this.realm,
      immediate,
      this.stateless,
      callback,
      this.extensions,
      this.strict,
    );
  };

  verifyAssertion = function (requestOrUrl, callback) {
    return this.openId.verifyAssertion(
      requestOrUrl,
      this.returnUrl,
      callback,
      this.stateless,
      this.extensions,
      this.strict,
    );
  };
}
