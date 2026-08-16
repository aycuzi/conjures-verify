// verify.conjures.net - standalone OAuth callback + landing service for the
// CONJURES Discord bot's custom Roblox verification system (replaces
// Bloxlink). This service does NOT initiate the OAuth flow - the Discord
// "Link Roblox Account" button links straight to Roblox's authorize screen
// (see conjuresbot's utils/robloxOAuth.js buildAuthorizeUrl). This service's
// only job is to receive Roblox's redirect back to /callback, exchange the
// code for the user's Roblox identity, and drop a row into the
// pending_verifications table for the bot to pick up and finish (grant role,
// set nickname, DM, etc). No session/cookie is ever used - the Discord user
// id travels through the OAuth `state` param, base64url-encoded, exactly as
// produced by robloxOAuth.js's makeState().
const express = require("express");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const { ROBLOX_OAUTH_CLIENT_ID, ROBLOX_OAUTH_CLIENT_SECRET, VERIFY_PUBLIC_URL, DATABASE_URL } = process.env;

const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL }) : null;

const TOKEN_URL = "https://apis.roblox.com/oauth/v1/token";
const USERINFO_URL = "https://apis.roblox.com/oauth/v1/userinfo";

function redirectUri() {
	return `${VERIFY_PUBLIC_URL || ""}/callback`;
}

function parseState(state) {
	try {
		const decoded = Buffer.from(state, "base64url").toString("utf8");
		const { discordUserId, nonce } = JSON.parse(decoded);
		if (!discordUserId || !nonce) return null;
		return { discordUserId, nonce };
	} catch {
		return null;
	}
}

function page(title, body) {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title} - Conjures Verify</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: radial-gradient(circle at top, #1a1230 0%, #0a0713 60%, #050308 100%);
    color: #e9e6f5; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 24px;
  }
  .card {
    max-width: 640px; width: 100%; background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 40px;
    backdrop-filter: blur(10px);
  }
  h1 { font-size: 1.6rem; margin: 0 0 12px; background: linear-gradient(90deg,#c084fc,#818cf8);
    -webkit-background-clip: text; background-clip: text; color: transparent; }
  h2 { font-size: 1.1rem; margin-top: 28px; color: #c4b5fd; }
  p, li { line-height: 1.6; color: #cbd0e0; }
  a { color: #a78bfa; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: rgba(168,139,250,0.15);
    color: #c4b5fd; font-size: 0.8rem; margin-bottom: 16px; }
  .footer { margin-top: 32px; font-size: 0.8rem; color: #6b7086; }
  .footer a { color: #8b90a8; }
</style>
</head>
<body>
  <div class="card">
    ${body}
    <div class="footer">Conjures &middot; <a href="/">Home</a> &middot; <a href="/privacy">Privacy Policy</a> &middot; <a href="/terms">Terms of Service</a></div>
  </div>
</body>
</html>`;
}

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/", (_req, res) => {
	res.send(
		page(
			"Home",
			`<span class="badge">Roblox Verification</span>
			<h1>Conjures Roblox Verification</h1>
			<p>This service links a Discord account to a Roblox account for the Conjures Discord server. It's used exclusively via the "Link Roblox Account" button on the Verification board in Discord - there's nothing to do here directly.</p>
			<p>If you were sent here after authorizing on Roblox, you can close this tab and return to Discord; your role and nickname will update automatically within a few seconds.</p>`
		)
	);
});

app.get("/privacy", (_req, res) => {
	res.send(
		page(
			"Privacy Policy",
			`<h1>Privacy Policy</h1>
			<p>Last updated: ${new Date().toISOString().slice(0, 10)}</p>
			<p>Conjures Verify ("this service") links a Discord account to a Roblox account for the Conjures Discord community.</p>
			<h2>What we collect</h2>
			<ul>
				<li>Your Roblox user ID, username, and display name (via Roblox's OAuth "openid profile" scope).</li>
				<li>Your Discord user ID (passed through the OAuth flow from Discord, never entered here).</li>
			</ul>
			<h2>What we don't collect</h2>
			<p>We never see your Roblox or Discord password, email, payment information, or any data beyond the public profile fields listed above. We do not use cookies or browser storage.</p>
			<h2>Our Commitment</h2>
			<p>Our privacy policy is simple. We do not collect any personal information from you. We do not use long term cookies. We do not track you. We do not store any information about you apart from your Roblox UserId and Discord UserId. We do not share any information about you with anyone. We do not sell any information about you to anyone.</p>
			<h2>How it's used</h2>
			<p>The linked Roblox user ID and username are stored so the Conjures Discord bot can assign a "Verified" role, set your Discord nickname to your Roblox username, and look up your in-game stats (coins, wins, inventory) for commands like <code>/my roblox</code>.</p>
			<h2>Retention</h2>
			<p>Your link is stored until you unlink your account (via the bot's unlink button) or a server administrator removes it.</p>
			<h2>Contact</h2>
			<p>Questions can be directed to the application owner, aycuzi on Roblox.</p>`
		)
	);
});

app.get("/terms", (_req, res) => {
	res.send(
		page(
			"Terms of Service",
			`<h1>Terms of Service</h1>
			<p>Last updated: ${new Date().toISOString().slice(0, 10)}</p>
			<p>By using Conjures Verify to link your Roblox account, you agree to the following:</p>
			<ul>
				<li>You are linking your own Roblox account, one you are authorized to use.</li>
				<li>Conjures server staff may unlink or re-link accounts at their discretion to enforce server rules.</li>
				<li>This service is provided as-is, with no guarantee of uptime, for the sole purpose of supporting the Conjures Discord community.</li>
				<li>Misuse (attempting to link accounts you don't own, exploiting the OAuth flow) may result in a ban from the Conjures Discord server and/or Roblox group.</li>
			</ul>
			<p>These terms may change at any time; continued use after a change constitutes acceptance.</p>`
		)
	);
});

app.get("/callback", async (req, res) => {
	const { code, state, error } = req.query;

	if (error) {
		return res.status(400).send(page("Verification Failed", `<h1>Verification Cancelled</h1><p>Roblox reported: <code>${String(error)}</code>. You can close this tab and try again from Discord.</p>`));
	}
	if (!code || !state) {
		return res.status(400).send(page("Verification Failed", `<h1>Invalid Request</h1><p>Missing <code>code</code> or <code>state</code>. Please start the verification flow again from Discord.</p>`));
	}

	const parsedState = parseState(String(state));
	if (!parsedState) {
		return res.status(400).send(page("Verification Failed", `<h1>Invalid Request</h1><p>The verification link has expired or was tampered with. Please start again from Discord.</p>`));
	}

	if (!ROBLOX_OAUTH_CLIENT_ID || !ROBLOX_OAUTH_CLIENT_SECRET || !VERIFY_PUBLIC_URL) {
		console.warn("[verify] missing ROBLOX_OAUTH_CLIENT_ID/SECRET/VERIFY_PUBLIC_URL");
		return res.status(500).send(page("Verification Failed", `<h1>Service Misconfigured</h1><p>This service is missing required configuration. Please contact Conjures staff.</p>`));
	}

	try {
		const tokenBody = new URLSearchParams({
			client_id: ROBLOX_OAUTH_CLIENT_ID,
			client_secret: ROBLOX_OAUTH_CLIENT_SECRET,
			grant_type: "authorization_code",
			code: String(code),
			redirect_uri: redirectUri(),
		});
		const tokenResponse = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: tokenBody.toString(),
		});
		if (!tokenResponse.ok) {
			const text2 = await tokenResponse.text().catch(() => "");
			console.warn(`[verify] token exchange failed ${tokenResponse.status}: ${text2}`);
			return res.status(502).send(page("Verification Failed", `<h1>Roblox Error</h1><p>Couldn't complete verification with Roblox. Please try again from Discord.</p>`));
		}
		const tokenData = await tokenResponse.json();

		const userResponse = await fetch(USERINFO_URL, {
			headers: { Authorization: `Bearer ${tokenData.access_token}` },
		});
		if (!userResponse.ok) {
			return res.status(502).send(page("Verification Failed", `<h1>Roblox Error</h1><p>Couldn't read your Roblox profile. Please try again from Discord.</p>`));
		}
		const userData = await userResponse.json();
		const robloxUserId = userData.sub;
		const robloxUsername = userData.preferred_username;

		if (!robloxUserId || !robloxUsername) {
			return res.status(502).send(page("Verification Failed", `<h1>Roblox Error</h1><p>Roblox didn't return a valid profile. Please try again from Discord.</p>`));
		}

		if (pool) {
			await pool.query(
				"insert into pending_verifications (discord_id, roblox_user_id, roblox_username) values ($1, $2, $3)",
				[parsedState.discordUserId, String(robloxUserId), robloxUsername]
			);
		} else {
			console.warn("[verify] DATABASE_URL missing - cannot record pending verification");
		}

		return res.send(
			page(
				"Verified",
				`<span class="badge">Success</span>
				<h1>Roblox account linked</h1>
				<p>Linked as <strong>${robloxUsername}</strong>. You can close this tab and return to Discord - your role and nickname will update within a few seconds.</p>`
			)
		);
	} catch (err) {
		console.error("[verify] callback failed -", err);
		return res.status(500).send(page("Verification Failed", `<h1>Something Went Wrong</h1><p>Please try again from Discord. If this keeps happening, contact Conjures staff.</p>`));
	}
});

app.listen(PORT, () => {
	console.log(`[verify] listening on ${PORT}`);
});
