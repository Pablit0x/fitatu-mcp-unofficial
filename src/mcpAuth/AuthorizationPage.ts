export interface AuthorizationPageOptions {
	readonly clientName: string;
	readonly redirectOrigin: string;
	readonly confirmPath: string;
	readonly sealedRequest: string;
	readonly errorMessage?: string;
}

export function renderAuthorizationPage(options: AuthorizationPageOptions): string {
	const error = options.errorMessage ? `<p class="error" role="alert">${escapeHtml(options.errorMessage)}</p>` : "";
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Authorize Fitatu MCP</title>
<style>
body { font-family: system-ui, sans-serif; background: #f4f4f5; color: #18181b; margin: 0; padding: 16px; }
main { max-width: 420px; margin: 10vh auto 0; background: #fff; border-radius: 12px; padding: 24px; }
h1 { font-size: 1.25rem; margin: 0 0 12px; }
p { line-height: 1.5; margin: 0 0 12px; }
code { overflow-wrap: anywhere; }
label { display: block; font-weight: 600; margin: 16px 0 6px; }
input { width: 100%; box-sizing: border-box; padding: 10px; font-size: 1rem; border: 1px solid #a1a1aa; border-radius: 8px; }
button { margin-top: 16px; width: 100%; padding: 10px; font-size: 1rem; border: 0; border-radius: 8px; background: #18181b; color: #fff; }
.error { color: #b91c1c; font-weight: 600; }
</style>
</head>
<body>
<main>
<h1>Authorize access to Fitatu MCP</h1>
<p><strong>${escapeHtml(options.clientName)}</strong> is asking to read and change data in the Fitatu account behind this server.</p>
<p>After approval you will be sent to <code>${escapeHtml(options.redirectOrigin)}</code>. Continue only if you started this connection yourself.</p>
${error}
<form method="post" action="${escapeHtml(options.confirmPath)}">
<input type="hidden" name="request" value="${escapeHtml(options.sealedRequest)}">
<label for="password">Server password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Authorize</button>
</form>
</main>
</body>
</html>`;
}

function escapeHtml(value: string): string {
	return value
		.replaceAll("&", "&amp;")
		.replaceAll("<", "&lt;")
		.replaceAll(">", "&gt;")
		.replaceAll('"', "&quot;")
		.replaceAll("'", "&#39;");
}
