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
			<p>Our privacy policy is simple. Conjures Verify only collects and stores the information necessary to provide Roblox account verification.</p>

			<h2>Information We Collect</h2>
			<ul>
				<li>Your Roblox User ID, username, and display name provided through Roblox OAuth.</li>
				<li>Your Discord User ID, provided by the Conjures verification system.</li>
			</ul>

			<h2>How We Use Your Information</h2>
			<p>We use this information to link your Roblox account to your Discord account, verify your identity within the Conjures community, assign Discord roles, set your Discord nickname, and provide related Conjures services.</p>

			<h2>What We Don't Collect</h2>
			<p>We do not collect or store your Roblox password, Discord password, payment information, or authentication credentials.</p>

			<h2>Cookies and Tracking</h2>
			<p>We do not use long-term cookies, advertising trackers, or tracking technologies for advertising purposes.</p>

			<h2>Sharing</h2>
			<p>We do not sell your information or share it with unrelated third parties for advertising or marketing purposes. Information may be processed by services necessary to operate Conjures Verify, such as Roblox, Discord, hosting, and database infrastructure.</p>

			<h2>Data Retention</h2>
			<p>Your Roblox and Discord account association is stored while necessary to provide Conjures verification services. You may request that your account association be removed by contacting aycuzi.</p>

			<h2>Changes</h2>
			<p>This Privacy Policy may be updated from time to time. Continued use of the Service after changes are published constitutes acceptance of the updated policy.</p>

			<h2>Contact</h2>
			<p>Questions or requests regarding this Privacy Policy may be directed to aycuzi.</p>`
		)
	);
});

app.get("/terms", (_req, res) => {
	res.send(
		page(
			"Terms of Service",
			`<h1>Terms of Service</h1>
			<p>Last updated: ${new Date().toISOString().slice(0, 10)}</p>
			<p>By using Conjures Verify, you agree to the following terms:</p>

			<ul>
				<li>You will only use the Service to link a Roblox account that you own or are authorized to use.</li>
				<li>You will not use the Service to violate Roblox's Terms of Use, Community Standards, Creator Third-Party App Policy, or any other Roblox rules or policies.</li>
				<li>You will not use the Service to violate Discord's Terms of Service, Community Guidelines, or any other Discord rules or policies.</li>
				<li>You will not use the Service to violate any applicable laws or regulations.</li>
				<li>You will not use the Service to violate the terms, rules, or policies of any other service used in connection with Conjures.</li>
				<li>You will not attempt to access, link, or use another person's Roblox or Discord account without authorization.</li>
				<li>You will not exploit, abuse, interfere with, or attempt to circumvent the security or authentication systems of Conjures, Roblox, Discord, or any related service.</li>
				<li>Conjures staff may unlink or relink accounts when reasonably necessary to enforce community rules, investigate abuse, correct errors, or maintain the Service.</li>
				<li>Violations of these Terms may result in restriction or termination of access to Conjures Verify and may result in moderation action within the Conjures Discord community or Roblox group.</li>
				<li>Conjures Verify is an independent third-party service and is not operated by, affiliated with, endorsed by, or sponsored by Roblox Corporation or Discord Inc.</li>
				<li>The Service is provided as-is and as-available without a guarantee of continuous uptime or error-free operation.</li>
			</ul>

			<p>These Terms may be updated or changed at any time. Continued use of the Service after changes are published constitutes acceptance of the updated Terms.</p>`
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
