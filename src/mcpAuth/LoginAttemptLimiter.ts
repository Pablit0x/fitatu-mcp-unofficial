const DEFAULT_MAX_FAILURES = 5;
const DEFAULT_WINDOW_MS = 15 * 60 * 1000;

/**
 * Process-wide limiter for failed owner-password attempts. The server has a single owner, so the limit is
 * global rather than per address: forwarded client addresses cannot be trusted enough to key on.
 */
export class LoginAttemptLimiter {
	private readonly maxFailures: number;
	private readonly windowMs: number;
	private failureTimestamps: number[] = [];

	public constructor(maxFailures: number = DEFAULT_MAX_FAILURES, windowMs: number = DEFAULT_WINDOW_MS) {
		this.maxFailures = maxFailures;
		this.windowMs = windowMs;
	}

	public isLocked(nowMs: number): boolean {
		this.failureTimestamps = this.failureTimestamps.filter((timestamp) => nowMs - timestamp < this.windowMs);
		return this.failureTimestamps.length >= this.maxFailures;
	}

	public recordFailure(nowMs: number): void {
		this.failureTimestamps.push(nowMs);
	}
}
