export class SocialAuthProvider {
  constructor() {
    this.providers = new Map();
  }

  async setupProvider(name, config) {
    const defaultStrategies = {
      google: {
        authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenURL: 'https://oauth2.googleapis.com/token',
        profileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
        scope: ['profile', 'email'],
      },
      github: {
        authorizationURL: 'https://github.com/login/oauth/authorize',
        tokenURL: 'https://github.com/login/oauth/access_token',
        profileURL: 'https://api.github.com/user',
        scope: ['user:email'],
      },
    };

    const strategy = defaultStrategies[name] || {};
    this.providers.set(name, {
      ...strategy,
      ...config,
    });
  }

  async getUserProfile(provider, token) {
    const config = this.providers.get(provider);
    if (!config) throw new Error(`Provider ${provider} not configured`);

    const response = await fetch(config.profileURL, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    return response.json();
  }

  getAuthorizationUrl(provider, state) {
    const config = this.providers.get(provider);
    if (!config) throw new Error(`Provider ${provider} not configured`);

    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: config.callbackURL,
      response_type: 'code',
      scope: config.scope.join(' '),
      state,
    });

    return `${config.authorizationURL}?${params.toString()}`;
  }

  async exchangeCode(provider, code) {
    const config = this.providers.get(provider);
    if (!config) throw new Error(`Provider ${provider} not configured`);

    const params = new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      redirect_uri: config.callbackURL,
      grant_type: 'authorization_code',
    });

    const response = await fetch(config.tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: params,
    });

    return response.json();
  }
}
