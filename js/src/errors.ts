/**
 * Base error class for all IdServer client errors.
 */
export class IdServerError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'IdServerError';
  }
}

/**
 * Thrown when the OIDC discovery document or JWKS cannot be fetched.
 */
export class DiscoveryError extends IdServerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'DiscoveryError';
  }
}

/**
 * Thrown when an authorization code / refresh token exchange fails.
 */
export class TokenExchangeError extends IdServerError {
  constructor(
    public readonly error: string,
    public readonly description: string | undefined,
    public readonly statusCode: number,
  ) {
    super(description ? `${error}: ${description}` : error);
    this.name = 'TokenExchangeError';
  }
}

/**
 * Thrown when a token fails signature or claim validation.
 */
export class InvalidTokenError extends IdServerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'InvalidTokenError';
  }
}

/**
 * Thrown when the userinfo endpoint returns an error.
 */
export class UserInfoError extends IdServerError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'UserInfoError';
  }
}
