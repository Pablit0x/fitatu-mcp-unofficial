import express, { type Request, type Response } from "express";
import { randomUUID } from "node:crypto";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { AUTHORIZATION_CONFIRM_PATH, SingleUserOAuthProvider } from "./mcpAuth/SingleUserOAuthProvider.ts";

const MCP_PATH = "/mcp";

const authorizationConfirmationSchema = z.object({
	request: z.string().min(1),
	password: z.string().min(1),
});

interface McpHttpLogger {
	info(bindings: Record<string, unknown>, message: string): void;
	warn(bindings: Record<string, unknown>, message: string): void;
	error(bindings: Record<string, unknown>, message: string): void;
}

interface ActiveSession {
	readonly server: McpServer;
	readonly transport: StreamableHTTPServerTransport;
}

export interface McpHttpOAuthOptions {
	readonly provider: SingleUserOAuthProvider;
	/** Public origin of this server as clients reach it, for example `https://example.onrender.com`. */
	readonly publicUrl: URL;
}

export interface McpHttpServerOptions {
	readonly createServer: () => McpServer;
	readonly logger?: McpHttpLogger;
	/** When set, every `/mcp` request must carry an access token issued by this provider. */
	readonly oauth?: McpHttpOAuthOptions;
}

const silentLogger: McpHttpLogger = {
	info: () => undefined,
	warn: () => undefined,
	error: () => undefined,
};

export class McpHttpServer {
	public readonly app = express();

	private readonly createServer: () => McpServer;
	private readonly logger: McpHttpLogger;
	private readonly sessions = new Map<string, ActiveSession>();

	public constructor(options: McpHttpServerOptions) {
		this.createServer = options.createServer;
		this.logger = options.logger ?? silentLogger;
		this.app.use(express.json());
		if (options.oauth) {
			this.enableOAuth(options.oauth);
		}
		this.app.post(MCP_PATH, (request, response) => this.handlePost(request, response));
		this.app.get(MCP_PATH, (request, response) => this.handleExistingSession(request, response));
		this.app.delete(MCP_PATH, (request, response) => this.handleExistingSession(request, response));
	}

	public get activeSessionCount(): number {
		return this.sessions.size;
	}

	public async closeSessions(): Promise<void> {
		const sessions = [...this.sessions.values()];
		await Promise.allSettled(sessions.map(({ server }) => server.close()));
		this.sessions.clear();
		this.logger.info({ sessionCount: sessions.length }, "MCP sessions closed");
	}

	private enableOAuth(oauth: McpHttpOAuthOptions): void {
		const resourceServerUrl = new URL(MCP_PATH, oauth.publicUrl);

		// The server is expected to sit behind the hosting platform's reverse proxy.
		this.app.set("trust proxy", 1);
		this.app.use(
			mcpAuthRouter({
				provider: oauth.provider,
				issuerUrl: oauth.publicUrl,
				resourceServerUrl,
				resourceName: "Fitatu MCP",
				// Client secrets are derived from the client id and stay valid until the password changes.
				clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
			}),
		);
		this.app.post(
			AUTHORIZATION_CONFIRM_PATH,
			express.urlencoded({ extended: false }),
			async (request, response) => {
				const confirmation = authorizationConfirmationSchema.safeParse(request.body);
				if (!confirmation.success) {
					response.status(400).type("text/plain").send("Invalid authorization form.");
					return;
				}
				try {
					await oauth.provider.confirmAuthorization(
						confirmation.data.request,
						confirmation.data.password,
						response,
					);
				} catch (error) {
					this.handleFailure(response, error);
				}
			},
		);
		this.app.use(
			MCP_PATH,
			requireBearerAuth({
				verifier: oauth.provider,
				resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceServerUrl),
			}),
		);
	}

	private async handlePost(request: Request, response: Response): Promise<void> {
		const sessionId = getSessionId(request);
		if (sessionId) {
			await this.handleExistingSession(request, response);
			return;
		}

		if (!isInitializeRequest(request.body)) {
			this.logger.warn({}, "MCP request rejected because no session id was provided");
			writeJsonRpcError(response, 400, -32000, "Mcp-Session-Id header is required");
			return;
		}

		await this.initializeSession(request, response);
	}

	private async initializeSession(request: Request, response: Response): Promise<void> {
		let activeSession: ActiveSession;
		const transport = new StreamableHTTPServerTransport({
			sessionIdGenerator: () => randomUUID(),
			onsessioninitialized: (sessionId) => {
				this.sessions.set(sessionId, activeSession);
				this.logger.info({ sessionId }, "MCP session initialized");
			},
		});
		const server = this.createServer();
		activeSession = { server, transport };

		transport.onclose = () => {
			const sessionId = transport.sessionId;
			if (sessionId && this.sessions.delete(sessionId)) {
				this.logger.info({ sessionId }, "MCP session closed");
			}
		};

		try {
			await server.connect(transport);
			await transport.handleRequest(request, response, request.body);
		} catch (error) {
			await server.close().catch(() => undefined);
			this.handleFailure(response, error);
		}
	}

	private async handleExistingSession(request: Request, response: Response): Promise<void> {
		const sessionId = getSessionId(request);
		if (!sessionId) {
			this.logger.warn({}, "MCP request rejected because no session id was provided");
			writeJsonRpcError(response, 400, -32000, "Mcp-Session-Id header is required");
			return;
		}

		const session = this.sessions.get(sessionId);
		if (!session) {
			this.logger.warn({ sessionId }, "MCP request rejected for an unknown session");
			writeJsonRpcError(response, 404, -32001, "Session not found");
			return;
		}

		try {
			await session.transport.handleRequest(request, response, request.body);
		} catch (error) {
			this.handleFailure(response, error);
		}
	}

	private handleFailure(response: Response, error: unknown): void {
		this.logger.error(
			{ errorName: error instanceof Error ? error.name : "UnknownError" },
			"Error handling MCP request",
		);
		if (!response.headersSent) {
			writeJsonRpcError(response, 500, -32603, "Internal server error");
		}
	}
}

function getSessionId(request: Request): string | undefined {
	const value = request.headers["mcp-session-id"];
	return typeof value === "string" && value ? value : undefined;
}

function writeJsonRpcError(response: Response, status: number, code: number, message: string): void {
	response.status(status).json({
		jsonrpc: "2.0",
		error: { code, message },
		id: null,
	});
}
