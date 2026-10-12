import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

const envelopeSchema = z.object({
	payload: z.unknown(),
	expiresAt: z.number().int().positive().optional(),
});

/**
 * Seals JSON payloads into tamper-proof strings so OAuth state survives process restarts without storage.
 * The purpose is part of the signature, so a value sealed for one purpose is never accepted for another.
 */
export class SignedPayloadCodec {
	private readonly key: Buffer;

	public constructor(key: Buffer) {
		this.key = key;
	}

	public seal(purpose: string, payload: unknown, expiresAt?: number): string {
		const body = Buffer.from(JSON.stringify({ payload, expiresAt })).toString("base64url");
		return `${body}.${this.sign(purpose, body)}`;
	}

	public open(purpose: string, sealed: string, nowSeconds: number): unknown {
		const separatorIndex = sealed.indexOf(".");
		if (separatorIndex <= 0) {
			return undefined;
		}

		const body = sealed.slice(0, separatorIndex);
		const expected = Buffer.from(this.sign(purpose, body));
		const actual = Buffer.from(sealed.slice(separatorIndex + 1));
		if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
			return undefined;
		}

		const envelope = envelopeSchema.safeParse(parseJson(Buffer.from(body, "base64url").toString("utf8")));
		if (!envelope.success) {
			return undefined;
		}
		if (envelope.data.expiresAt !== undefined && envelope.data.expiresAt <= nowSeconds) {
			return undefined;
		}
		return envelope.data.payload;
	}

	public sign(purpose: string, value: string): string {
		return createHmac("sha256", this.key).update(`${purpose}.${value}`).digest("base64url");
	}
}

function parseJson(text: string): unknown {
	try {
		return JSON.parse(text);
	} catch {
		return undefined;
	}
}
