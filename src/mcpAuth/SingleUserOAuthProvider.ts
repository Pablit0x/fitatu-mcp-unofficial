import { createHash, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import type { Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
	InvalidClientMetadataError,
	InvalidGrantError,
	InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { z } from "zod";
import { renderAuthorizationPage } from "./AuthorizationPage.ts";
import { LoginAttemptLimiter } from "./LoginAttemptLimiter.ts";
import { SignedPayloadCodec } from "./SignedPayloadCodec.ts";

export const AUTHORIZATION_CONFIRM_PATH = "/oauth/confirm";

const KEY_DERIVATION_SALT = "fitatu-mcp-oauth-v1";
// scrypt makes every offline guess of the owner password expensive, because signed values are public.
const KEY_DERIVATION_COST = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const AUTHORIZATION_REQUEST_TTL_SECONDS = 10 * 60;
const AUTHORIZATION_CODE_TTL_SECONDS = 5 * 60;
const ACCESS_TOKEN_TTL_SECONDS = 60 * 60;
const REFRESH_TOKEN_TTL_SECONDS = 60 * 24 * 60 * 60;
const MAX_REDIRECT_URIS = 10;
const MAX_REDIRECT_URI_LENGTH = 2000;
const MAX_CLIENT_NAME_LENGTH = 100;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

const clientPayloadSchema = z.object({
	redirectUris: z.array(z.string()).min(1),
	clientName: z.string().optional(),
	tokenEndpointAuthMethod: z.string().optional(),
	hasSecret: z.boolean(),
	issuedAt: z.number().int(),
});

const authorizationRequestPayloadSchema = z.object({
	clientId: z.string(),
	redirectUri: z.string(),
	codeChallenge: z.string(),
	state: z.string().optional(),
	resource: z.string().optional(),
});

const authorizationCodePayloadSchema = z.object({
	id: z.string(),
	clientId: z.string(),
	redirectUri: z.string(),
	codeChallenge: z.string(),
	resource: z.string().optional(),
});

const tokenPayloadSchema = z.object({
	clientId: z.string(),
	resource: z.string().optional(),
	expiresAt: z.number().int(),
});

type ClientPayload = z.infer<typeof clientPayloadSchema>;
type AuthorizationCodePayload = z.infer<typeof authorizationCodePayloadSchema>;

export interface SingleUserOAuthLogger {
	info(bindings: Record<string, unknown>, message: string): void;
	warn(bindings: Record<string, unknown>, message: string): void;
}

export interface SingleUserOAuthProviderOptions {
	readonly ownerPassword: string;
	readonly allowedRedirectHosts: readonly string[];
	readonly logger: SingleUserOAuthLogger;
	readonly loginAttemptLimiter?: LoginAttemptLimiter;
}

/**
 * OAuth 2.1 authorization server for a server with exactly one owner. The owner approves each client by
 * typing the server password. Clients, codes, and tokens are signed values instead of stored records, so
 * they stay valid across restarts of a host that sleeps; changing the password invalidates all of them.
 */
export class SingleUserOAuthProvider implements OAuthServerProvider, OAuthRegisteredClientsStore {
	private readonly ownerPasswordDigest: Buffer;
	private readonly allowedRedirectHosts: ReadonlySet<string>;
	private readonly codec: SignedPayloadCodec;
	private readonly logger: SingleUserOAuthLogger;
	private readonly loginAttemptLimiter: LoginAttemptLimiter;
	private readonly usedAuthorizationCodes = new Map<string, number>();

	public constructor(options: SingleUserOAuthProviderOptions) {
		this.ownerPasswordDigest = digest(options.ownerPassword);
		this.allowedRedirectHosts = new Set(options.allowedRedirectHosts.map((host) => host.toLowerCase()));
		this.codec = new SignedPayloadCodec(
			scryptSync(options.ownerPassword, KEY_DERIVATION_SALT, 32, KEY_DERIVATION_COST),
		);
		this.logger = options.logger;
		this.loginAttemptLimiter = options.loginAttemptLimiter ?? new LoginAttemptLimiter();
	}

	public get clientsStore(): OAuthRegisteredClientsStore {
		return this;
	}

	public getClient(clientId: string): OAuthClientInformationFull | undefined {
		const payload = clientPayloadSchema.safeParse(this.codec.open("client", clientId, nowSeconds()));
		return payload.success ? this.toClientInformation(clientId, payload.data) : undefined;
	}

	public registerClient(
		client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">,
	): OAuthClientInformationFull {
		if (client.redirect_uris.length > MAX_REDIRECT_URIS) {
			throw new InvalidClientMetadataError("Too many redirect URIs");
		}
		for (const redirectUri of client.redirect_uris) {
			if (!this.isAllowedRedirectUri(redirectUri)) {
				throw new InvalidClientMetadataError("Redirect URI is not allowed by this server");
			}
		}

		const payload: ClientPayload = {
			redirectUris: client.redirect_uris,
			clientName: client.client_name?.slice(0, MAX_CLIENT_NAME_LENGTH),
			tokenEndpointAuthMethod: client.token_endpoint_auth_method,
			hasSecret: client.client_secret !== undefined,
			issuedAt: nowSeconds(),
		};
		const clientId = this.codec.seal("client", payload);
		this.logger.info({ clientName: payload.clientName }, "OAuth client registered");
		return this.toClientInformation(clientId, payload);
	}

	public async authorize(
		client: OAuthClientInformationFull,
		params: AuthorizationParams,
		response: Response,
	): Promise<void> {
		const sealedRequest = this.codec.seal(
			"authorization-request",
			{
				clientId: client.client_id,
				redirectUri: params.redirectUri,
				codeChallenge: params.codeChallenge,
				state: params.state,
				resource: params.resource?.href,
			},
			nowSeconds() + AUTHORIZATION_REQUEST_TTL_SECONDS,
		);
		this.sendAuthorizationPage(response, 200, client, params.redirectUri, sealedRequest);
	}

	/** Handles the password form posted from the authorization page. */
	public async confirmAuthorization(sealedRequest: string, password: string, response: Response): Promise<void> {
		const request = authorizationRequestPayloadSchema.safeParse(
			this.codec.open("authorization-request", sealedRequest, nowSeconds()),
		);
		const client = request.success ? this.getClient(request.data.clientId) : undefined;
		if (!request.success || !client) {
			sendPlainText(response, 400, "This authorization request is invalid or has expired. Start again.");
			return;
		}

		const nowMs = Date.now();
		if (this.loginAttemptLimiter.isLocked(nowMs)) {
			this.logger.warn({}, "OAuth authorization rejected because of too many failed attempts");
			this.sendAuthorizationPage(
				response,
				429,
				client,
				request.data.redirectUri,
				sealedRequest,
				"Too many failed attempts. Try again in 15 minutes.",
			);
			return;
		}
		if (!timingSafeEqual(digest(password), this.ownerPasswordDigest)) {
			this.loginAttemptLimiter.recordFailure(nowMs);
			this.logger.warn({}, "OAuth authorization rejected because of a wrong password");
			this.sendAuthorizationPage(
				response,
				401,
				client,
				request.data.redirectUri,
				sealedRequest,
				"Wrong password.",
			);
			return;
		}

		const code = this.codec.seal(
			"authorization-code",
			{
				id: randomUUID(),
				clientId: request.data.clientId,
				redirectUri: request.data.redirectUri,
				codeChallenge: request.data.codeChallenge,
				resource: request.data.resource,
			},
			nowSeconds() + AUTHORIZATION_CODE_TTL_SECONDS,
		);
		const redirectUrl = new URL(request.data.redirectUri);
		redirectUrl.searchParams.set("code", code);
		if (request.data.state !== undefined) {
			redirectUrl.searchParams.set("state", request.data.state);
		}
		this.logger.info({ clientName: client.client_name }, "OAuth authorization approved");
		response.setHeader("Cache-Control", "no-store");
		response.redirect(302, redirectUrl.href);
	}

	public async challengeForAuthorizationCode(
		client: OAuthClientInformationFull,
		authorizationCode: string,
	): Promise<string> {
		return this.openAuthorizationCode(client, authorizationCode).codeChallenge;
	}

	public async exchangeAuthorizationCode(
		client: OAuthClientInformationFull,
		authorizationCode: string,
		_codeVerifier?: string,
		redirectUri?: string,
	): Promise<OAuthTokens> {
		const code = this.openAuthorizationCode(client, authorizationCode);
		if (redirectUri !== undefined && redirectUri !== code.redirectUri) {
			throw new InvalidGrantError("redirect_uri does not match the authorization request");
		}

		const now = nowSeconds();
		this.forgetExpiredAuthorizationCodes(now);
		if (this.usedAuthorizationCodes.has(code.id)) {
			throw new InvalidGrantError("Authorization code has already been used");
		}
		this.usedAuthorizationCodes.set(code.id, now + AUTHORIZATION_CODE_TTL_SECONDS);

		return this.issueTokens(client.client_id, code.resource);
	}

	public async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
		const token = tokenPayloadSchema.safeParse(this.codec.open("refresh-token", refreshToken, nowSeconds()));
		if (!token.success || token.data.clientId !== client.client_id) {
			throw new InvalidGrantError("Invalid refresh token");
		}
		return this.issueTokens(client.client_id, token.data.resource);
	}

	public async verifyAccessToken(token: string): Promise<AuthInfo> {
		const payload = tokenPayloadSchema.safeParse(this.codec.open("access-token", token, nowSeconds()));
		if (!payload.success || !this.getClient(payload.data.clientId)) {
			throw new InvalidTokenError("Invalid or expired access token");
		}
		return {
			token,
			clientId: payload.data.clientId,
			scopes: [],
			expiresAt: payload.data.expiresAt,
			resource: payload.data.resource ? new URL(payload.data.resource) : undefined,
		};
	}

	private issueTokens(clientId: string, resource: string | undefined): OAuthTokens {
		const now = nowSeconds();
		const accessExpiresAt = now + ACCESS_TOKEN_TTL_SECONDS;
		const refreshExpiresAt = now + REFRESH_TOKEN_TTL_SECONDS;
		return {
			access_token: this.codec.seal(
				"access-token",
				{ clientId, resource, expiresAt: accessExpiresAt },
				accessExpiresAt,
			),
			token_type: "Bearer",
			expires_in: ACCESS_TOKEN_TTL_SECONDS,
			refresh_token: this.codec.seal(
				"refresh-token",
				{ clientId, resource, expiresAt: refreshExpiresAt },
				refreshExpiresAt,
			),
		};
	}

	private openAuthorizationCode(
		client: OAuthClientInformationFull,
		authorizationCode: string,
	): AuthorizationCodePayload {
		const code = authorizationCodePayloadSchema.safeParse(
			this.codec.open("authorization-code", authorizationCode, nowSeconds()),
		);
		if (!code.success || code.data.clientId !== client.client_id) {
			throw new InvalidGrantError("Invalid or expired authorization code");
		}
		return code.data;
	}

	private forgetExpiredAuthorizationCodes(now: number): void {
		for (const [id, expiresAt] of this.usedAuthorizationCodes) {
			if (expiresAt <= now) {
				this.usedAuthorizationCodes.delete(id);
			}
		}
	}

	private toClientInformation(clientId: string, payload: ClientPayload): OAuthClientInformationFull {
		return {
			client_id: clientId,
			client_id_issued_at: payload.issuedAt,
			// Derived from the client id, so it can be recomputed instead of stored. Zero means it never expires.
			client_secret: payload.hasSecret ? this.codec.sign("client-secret", clientId) : undefined,
			client_secret_expires_at: payload.hasSecret ? 0 : undefined,
			redirect_uris: payload.redirectUris,
			client_name: payload.clientName,
			token_endpoint_auth_method: payload.tokenEndpointAuthMethod,
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
		};
	}

	private isAllowedRedirectUri(redirectUri: string): boolean {
		if (redirectUri.length > MAX_REDIRECT_URI_LENGTH || !URL.canParse(redirectUri)) {
			return false;
		}
		const url = new URL(redirectUri);
		if (LOOPBACK_HOSTS.has(url.hostname)) {
			return url.protocol === "http:" || url.protocol === "https:";
		}
		return url.protocol === "https:" && this.allowedRedirectHosts.has(url.hostname.toLowerCase());
	}

	private sendAuthorizationPage(
		response: Response,
		status: number,
		client: OAuthClientInformationFull,
		redirectUri: string,
		sealedRequest: string,
		errorMessage?: string,
	): void {
		const redirectOrigin = new URL(redirectUri).origin;
		response.status(status);
		response.setHeader("Cache-Control", "no-store");
		response.setHeader("Referrer-Policy", "no-referrer");
		response.setHeader("X-Content-Type-Options", "nosniff");
		// form-action must include the redirect origin: browsers apply it to the redirect that follows the form.
		response.setHeader(
			"Content-Security-Policy",
			`default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' ${redirectOrigin}`,
		);
		response.type("html").send(
			renderAuthorizationPage({
				clientName: client.client_name ?? "An MCP client",
				redirectOrigin,
				confirmPath: AUTHORIZATION_CONFIRM_PATH,
				sealedRequest,
				errorMessage,
			}),
		);
	}
}

function digest(value: string): Buffer {
	return createHash("sha256").update(value).digest();
}

function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

function sendPlainText(response: Response, status: number, message: string): void {
	response.status(status).setHeader("Cache-Control", "no-store");
	response.type("text/plain").send(message);
}
