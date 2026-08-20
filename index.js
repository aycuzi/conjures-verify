// verify.conjures.net - standalone OAuth callback + landing service for the
// CONJURES Discord bot's custom Roblox account-linking system.
//
// There are two OAuth entry paths:
//
// 1. Discord verification:
//    Discord -> Roblox -> /callback -> pending_verifications -> Discord bot
//
// 2. Public OAuth Entry Link:
//    / -> /login -> Roblox -> /callback -> public success page
//
// IMPORTANT:
// - Both flows request ONLY the Roblox OAuth scopes required for Account
//   Linking Tools: "openid profile".
// - The public Entry Link flow does NOT receive a Discord ID.
// - The public Entry Link flow does NOT create a Discord/Roblox association.
// - The public Entry Link flow does NOT write to pending_verifications.
// - The public Entry Link flow does NOT assign Discord roles or nicknames.
// - The public Entry Link flow only demonstrates the Roblox authentication
//   portion of the account-linking service.
//
// The Discord verification flow is intentionally kept separate from the
// public reviewer flow.
//
// Roblox account identity is based on the Roblox OAuth "sub" value (Roblox
// User ID). Username/display name are display information only.

const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const {
	ROBLOX_OAUTH_CLIENT_ID,
	ROBLOX_OAUTH_CLIENT_SECRET,
	VERIFY_PUBLIC_URL,
	DATABASE_URL,
} = process.env;

const pool = DATABASE_URL
	? new Pool({ connectionString: DATABASE_URL })
	: null;

const AUTHORIZE_URL = "https://apis.roblox.com/oauth/v1/authorize";
const TOKEN_URL = "https://apis.roblox.com/oauth/v1/token";
const USERINFO_URL = "https://apis.roblox.com/oauth/v1/userinfo";

// Account Linking Tools only require these scopes.
// DO NOT add additional Roblox OAuth scopes here.
const ROBLOX_OAUTH_SCOPE = "openid profile";

function redirectUri() {
	return `${VERIFY_PUBLIC_URL || ""}/callback`;
}

// -----------------------------------------------------------------------------
// Discord OAuth state parser
// -----------------------------------------------------------------------------
//
// IMPORTANT:
// This function is intentionally left compatible with the existing Discord
// verification flow.
//
// The Discord bot creates this state and the callback uses it to recover the
// Discord user ID.
//
// Do not change the Discord OAuth initiation flow in this file.
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Public OAuth Entry Link state
// -----------------------------------------------------------------------------
//
// These states are ONLY for the public Entry Link:
//
// https://verify.conjures.net/
//
// They are completely separate from the Discord verification state.
//
// They are:
// - cryptographically random
// - temporary
// - single-use
// - NOT associated with a Discord ID
// - NEVER inserted into pending_verifications
// - NEVER used to assign Discord roles
// - NEVER used to change Discord nicknames
//
// A Railway restart clears these temporary states, which is acceptable because
// they are only short-lived authentication sessions.
// -----------------------------------------------------------------------------

const webOAuthStates = new Map();

function createWebOAuthState() {
	const state = crypto.randomBytes(32).toString("base64url");

	webOAuthStates.set(state, {
		createdAt: Date.now(),
	});

	return state;
}

// Clean up old public OAuth states periodically.
setInterval(() => {
	const expiration = 10 * 60 * 1000;
	const now = Date.now();

	for (const [state, data] of webOAuthStates.entries()) {
		if (now - data.createdAt > expiration) {
			webOAuthStates.delete(state);
		}
	}
}, 60 * 1000);

// -----------------------------------------------------------------------------
// HTML page helper
// -----------------------------------------------------------------------------

function escapeHtml(value) {
	return String(value)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#039;");
}

function page(title, body) {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="description" content="Conjures Roblox account linking service." />
<title>${escapeHtml(title)} - Conjures Verify</title>
<style>
  :root {
	color-scheme: dark;
  }

  * {
	box-sizing: border-box;
  }

  body {
	margin: 0;
	min-height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	background: radial-gradient(
		circle at top,
		#1a1230 0%,
		#0a0713 60%,
		#050308 100%
	);
	color: #e9e6f5;
	font-family:
		-apple-system,
		BlinkMacSystemFont,
		"Segoe UI",
		Roboto,
		sans-serif;
	padding: 24px;
  }

  .card {
	max-width: 680px;
	width: 100%;
	background: rgba(255,255,255,0.04);
	border: 1px solid rgba(255,255,255,0.08);
	border-radius: 16px;
	padding: 40px;
	backdrop-filter: blur(10px);
  }

  h1 {
	font-size: 1.6rem;
	margin: 0 0 12px;
	background: linear-gradient(90deg,#c084fc,#818cf8);
	-webkit-background-clip: text;
	background-clip: text;
	color: transparent;
  }

  h2 {
	font-size: 1.1rem;
	margin-top: 28px;
	color: #c4b5fd;
  }

  p, li {
	line-height: 1.6;
	color: #cbd0e0;
  }

  a {
	color: #a78bfa;
  }

  code {
	color: #ddd6fe;
	background: rgba(255,255,255,0.06);
	padding: 2px 5px;
	border-radius: 4px;
  }

  .badge {
	display: inline-block;
	padding: 4px 10px;
	border-radius: 999px;
	background: rgba(168,139,250,0.15);
	color: #c4b5fd;
	font-size: 0.8rem;
	margin-bottom: 16px;
  }

  .button {
	display: inline-block;
	padding: 12px 20px;
	border-radius: 10px;
	background: #a78bfa;
	color: white;
	text-decoration: none;
	font-weight: 600;
  }

  .button:hover {
	background: #8b5cf6;
  }

  .scope-box {
	margin-top: 24px;
	padding: 16px;
	border-radius: 10px;
	background: rgba(167,139,250,0.08);
	border: 1px solid rgba(167,139,250,0.15);
  }

  .scope-box strong {
	color: #ddd6fe;
  }

  .footer {
	margin-top: 32px;
	font-size: 0.8rem;
	color: #6b7086;
  }

  .footer a {
	color: #8b90a8;
  }
</style>
</head>
<body>
  <div class="card">
	${body}

	<div class="footer">
		Conjures &middot;
		<a href="/">Home</a> &middot;
		<a href="/privacy">Privacy Policy</a> &middot;
		<a href="/terms">Terms of Service</a>
	</div>
  </div>
</body>
</html>`;
}

// -----------------------------------------------------------------------------
// Health check
// -----------------------------------------------------------------------------

app.get("/health", (_req, res) => {
	res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// Public Home / Roblox OAuth Entry Link
// -----------------------------------------------------------------------------
//
// This is the reviewer-facing/public entry point.
//
// It starts the Roblox authentication portion of the account-linking service,
// but because there is no Discord account associated with this direct entry,
// it intentionally does NOT create a link or write verification data.
// -----------------------------------------------------------------------------

app.get("/", (_req, res) => {
	res.send(
		page(
			"Roblox Account Linking",
			`<span class="badge">Account Linking Tool</span>

			<h1>Conjures Roblox Account Linking</h1>

			<p>
				Conjures allows members of the Conjures community to securely
				link their Roblox account with their Discord account.
			</p>

			<p>
				Roblox OAuth is used to authenticate the user's Roblox account
				and obtain the profile information required for account linking.
			</p>

			<div class="scope-box">
				<strong>Roblox OAuth permissions</strong>

				<p style="margin-bottom: 0;">
					This application requests only the
					<code>openid</code> and <code>profile</code> scopes.
					These scopes are used to authenticate the user and
					identify the Roblox account being linked.
				</p>
			</div>

			<p style="margin-top: 28px;">
				<a href="/login" class="button">
					Continue with Roblox
				</a>
			</p>

			<p style="font-size: 0.9rem; margin-top: 24px;">
				By continuing, you agree to the
				<a href="/terms">Terms of Service</a>
				and acknowledge the
				<a href="/privacy">Privacy Policy</a>.
			</p>

			<p style="font-size: 0.85rem; margin-top: 20px;">
				Conjures Verify is an independent third-party application
				and is not affiliated with, endorsed by, or sponsored by
				Roblox Corporation.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Public OAuth Login
// -----------------------------------------------------------------------------
//
// IMPORTANT:
//
// This route is ONLY for the public Roblox OAuth Entry Link.
//
// It:
// - does NOT receive a Discord ID
// - does NOT create a Discord association
// - does NOT write to pending_verifications
// - does NOT assign Discord roles
// - does NOT modify Discord nicknames
// - does NOT perform any additional Roblox API authorization
//
// It simply starts the same Roblox OAuth authorization request used to
// authenticate the Roblox account for the account-linking service.
// -----------------------------------------------------------------------------

app.get("/login", (_req, res) => {
	if (!ROBLOX_OAUTH_CLIENT_ID || !VERIFY_PUBLIC_URL) {
		return res.status(500).send(
			page(
				"Unable to Continue",
				`<h1>Service Misconfigured</h1>

				<p>
					This verification service is missing required configuration.
					Please try again later.
				</p>`
			)
		);
	}

	const state = createWebOAuthState();

	const params = new URLSearchParams({
		client_id: ROBLOX_OAUTH_CLIENT_ID,
		redirect_uri: redirectUri(),

		// Account Linking Tools:
		// ONLY openid + profile.
		scope: ROBLOX_OAUTH_SCOPE,

		response_type: "code",
		state,
	});

	const authorizeUrl = `${AUTHORIZE_URL}?${params.toString()}`;

	return res.redirect(authorizeUrl);
});

// -----------------------------------------------------------------------------
// Privacy Policy
// -----------------------------------------------------------------------------

app.get("/privacy", (_req, res) => {
	res.send(
		page(
			"Privacy Policy",
			`<h1>Privacy Policy</h1>

			<p>
				Last updated: ${new Date().toISOString().slice(0, 10)}
			</p>

			<p>
				Conjures Verify is a third-party account-linking service
				that allows users to authenticate their Roblox account and
				link it with their Discord account for use within the
				Conjures community.
			</p>

			<h2>Information We Collect</h2>

			<p>
				When you authenticate with Roblox through Conjures Verify,
				we receive the information made available through the
				Roblox OAuth permissions requested by the application.
				These permissions are limited to <code>openid</code> and
				<code>profile</code>.
			</p>

			<p>
				This may include:
			</p>

			<ul>
				<li>Your Roblox User ID.</li>
				<li>Your Roblox username.</li>
				<li>Your Roblox display name, when provided by Roblox.</li>
			</ul>

			<p>
				When you use the Conjures account-linking and verification
				system, we may also process your Discord User ID so that
				your Roblox account can be associated with your Discord
				account.
			</p>

			<h2>Roblox OAuth Permissions</h2>

			<p>
				Conjures Verify requests only the
				<code>openid</code> and <code>profile</code> Roblox OAuth
				scopes.
			</p>

			<p>
				These permissions are used to authenticate the user and
				obtain the Roblox profile information necessary to identify
				the Roblox account being linked.
			</p>

			<h2>How We Use Your Information</h2>

			<p>
				We use the information described in this Privacy Policy
				for the operation of the Conjures account-linking and
				verification service.
			</p>

			<p>
				This may include:
			</p>

			<ul>
				<li>
					Authenticating your Roblox account through Roblox OAuth.
				</li>
				<li>
					Identifying the Roblox account being linked.
				</li>
				<li>
					Associating your Roblox account with your Discord account.
				</li>
				<li>
					Verifying your account within the Conjures community.
				</li>
				<li>
					Maintaining the account association required to provide
					the Conjures verification service.
				</li>
				<li>
					Providing related Conjures community functionality,
					such as Discord role or nickname management where
					applicable.
				</li>
			</ul>

			<h2>Information We Do Not Collect</h2>

			<p>
				Conjures Verify does not request or store your Roblox
				password, Discord password, payment information, or
				authentication credentials.
			</p>

			<h2>Cookies and Tracking</h2>

			<p>
				Conjures Verify does not use advertising trackers or
				tracking technologies to track users for advertising or
				profiling purposes.
			</p>

			<p>
				The service may use temporary technical authentication
				state during the Roblox OAuth process. This temporary
				state is used only to securely complete an authentication
				request and is not used for advertising or user tracking.
			</p>

			<h2>Sharing of Information</h2>

			<p>
				We do not sell your information.
			</p>

			<p>
				We do not share Roblox account information with unrelated
				third parties for advertising or marketing purposes.
			</p>

			<p>
				Information may be processed by service providers necessary
				to operate Conjures Verify, including Roblox, Discord,
				hosting infrastructure, and database infrastructure.
			</p>

			<h2>Data Retention</h2>

			<p>
				Roblox and Discord account-linking information is retained
				for as long as reasonably necessary to provide the Conjures
				account-linking and verification service.
			</p>

			<p>
				Temporary OAuth authentication state is retained only for
				the period necessary to complete the authentication process
				and is automatically removed after it expires or is used.
			</p>

			<h2>Data Deletion</h2>

			<p>
				You may request removal of your Roblox and Discord
				account-linking information by contacting Conjures staff.
			</p>

			<p>
				Requests will be reviewed and handled as reasonably
				necessary to remove the information associated with the
				Conjures account-linking service.
			</p>

			<h2>Security</h2>

			<p>
				Conjures Verify uses reasonable technical measures to
				protect information processed through the service.
			</p>

			<p>
				Roblox passwords, Discord passwords, and OAuth client
				secrets are not provided to or stored by users of the
				service.
			</p>

			<h2>Changes to This Privacy Policy</h2>

			<p>
				This Privacy Policy may be updated from time to time.
				When changes are made, the updated policy will be published
				on this page with a new effective date.
			</p>

			<h2>Contact</h2>

			<p>
				Questions or requests regarding this Privacy Policy or
				your account-linking information may be directed to
				Conjures staff.
			</p>

			<p>
				Conjures Verify is an independent third-party application
				and is not affiliated with, endorsed by, or sponsored by
				Roblox Corporation.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Terms of Service
// -----------------------------------------------------------------------------

app.get("/terms", (_req, res) => {
	res.send(
		page(
			"Terms of Service",
			`<h1>Terms of Service</h1>

			<p>
				Last updated: ${new Date().toISOString().slice(0, 10)}
			</p>

			<p>
				These Terms of Service govern your use of Conjures Verify.
				By accessing or using Conjures Verify, you agree to these
				Terms of Service.
			</p>

			<h2>1. Description of the Service</h2>

			<p>
				Conjures Verify is a third-party account-linking service
				that allows users to authenticate their Roblox account
				through Roblox OAuth and link that Roblox account with
				their Discord account for use within the Conjures community.
			</p>

			<p>
				Conjures Verify requests only the Roblox OAuth
				<code>openid</code> and <code>profile</code> scopes.
			</p>

			<h2>2. Authorized Account Use</h2>

			<ul>
				<li>
					You may only link a Roblox account that you own or
					are authorized to use.
				</li>

				<li>
					You may only use Conjures Verify for your own account
					or with appropriate authorization from the account
					owner.
				</li>

				<li>
					You must not attempt to access, link, or use another
					person's Roblox or Discord account without authorization.
				</li>
			</ul>

			<h2>3. Roblox Terms and Policies</h2>

			<p>
				Your use of Conjures Verify must comply with the applicable
				Roblox Terms of Use, Community Standards, and other
				applicable Roblox policies.
			</p>

			<p>
				You must not use Conjures Verify to circumvent Roblox
				security systems, obtain unauthorized access to accounts,
				or otherwise violate Roblox policies.
			</p>

			<h2>4. Discord Terms and Policies</h2>

			<p>
				Your use of Conjures Verify in connection with Discord must
				comply with Discord's applicable Terms of Service,
				Community Guidelines, and other applicable Discord policies.
			</p>

			<h2>5. Prohibited Use</h2>

			<p>
				You must not use Conjures Verify to:
			</p>

			<ul>
				<li>
					Access or link an account without authorization.
				</li>

				<li>
					Attempt to obtain another person's authentication
					credentials or account information.
				</li>

				<li>
					Exploit, abuse, interfere with, or circumvent the
					security or authentication systems of Conjures,
					Roblox, Discord, or related services.
				</li>

				<li>
					Use the service for unlawful purposes.
				</li>

				<li>
					Violate the policies or terms of Roblox, Discord,
					or another service used in connection with Conjures.
				</li>
			</ul>

			<h2>6. Account Linking</h2>

			<p>
				When you authorize Conjures Verify through Roblox OAuth,
				the service may receive the Roblox profile information
				described in the Privacy Policy.
			</p>

			<p>
				When the account-linking process is completed, the
				Roblox account may be associated with your Discord
				account for purposes of Conjures verification and related
				community functionality.
			</p>

			<h2>7. Community Administration</h2>

			<p>
				Conjures staff may unlink or relink accounts when
				reasonably necessary to correct errors, maintain the
				service, investigate abuse, or enforce applicable
				Conjures community rules.
			</p>

			<h2>8. Privacy</h2>

			<p>
				Your use of Conjures Verify is also governed by our
				Privacy Policy, which explains what information we
				collect, how we use it, how it is retained, and how
				you may request its removal.
			</p>

			<h2>9. Third-Party Services</h2>

			<p>
				Conjures Verify interacts with third-party services,
				including Roblox and Discord. Your use of those services
				is also subject to their respective terms, policies,
				and requirements.
			</p>

			<h2>10. Relationship With Roblox</h2>

			<p>
				These Terms of Service are between you and the operator
				of Conjures Verify only. Roblox Corporation is not a party
				to these Terms of Service.
			</p>

			<p>
				Conjures Verify is an independent third-party application
				and is not affiliated with, endorsed by, sponsored by,
				or operated by Roblox Corporation.
			</p>

			<p>
				Roblox is not responsible or liable for your use of
				Conjures Verify and does not provide maintenance or
				support services for Conjures Verify.
			</p>

			<p>
				By using Conjures Verify, you acknowledge that Roblox
				is not responsible for the application or your use of
				the application.
			</p>

			<h2>11. Relationship With Discord</h2>

			<p>
				Conjures Verify is also independent from Discord Inc.
				and is not affiliated with, endorsed by, sponsored by,
				or operated by Discord Inc.
			</p>

			<h2>12. Service Availability</h2>

			<p>
				Conjures Verify is provided on an as-is and as-available
				basis. We do not guarantee that the service will always
				be available, uninterrupted, or error-free.
			</p>

			<h2>13. Changes to These Terms</h2>

			<p>
				These Terms of Service may be updated from time to time.
				When changes are made, the updated Terms will be published
				on this page with a new effective date.
			</p>

			<p>
				Your continued use of Conjures Verify after updated Terms
				are published constitutes acceptance of the updated Terms.
			</p>

			<h2>14. Contact</h2>

			<p>
				Questions regarding these Terms of Service may be directed
				to Conjures staff.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Roblox OAuth Callback
// -----------------------------------------------------------------------------
//
// IMPORTANT:
// The public Entry Link flow and the Discord verification flow are separated
// by the server-side public OAuth state.
//
// PUBLIC FLOW:
//   / -> /login -> Roblox -> /callback
//   -> authenticate only
//   -> NO database write
//   -> NO Discord association
//
// DISCORD FLOW:
//   Discord -> Roblox -> /callback
//   -> existing Discord state parsing
//   -> existing pending_verifications behavior
//
// The Discord verification behavior below is intentionally preserved.
// -----------------------------------------------------------------------------

app.get("/callback", async (req, res) => {
	const { code, state, error } = req.query;

	if (error) {
		return res.status(400).send(
			page(
				"Verification Failed",
				`<h1>Verification Cancelled</h1>

				<p>
					Roblox reported:
					<code>${escapeHtml(error)}</code>.
				</p>

				<p>
					You can close this tab and try again.
				</p>`
			)
		);
	}

	if (!code || !state) {
		return res.status(400).send(
			page(
				"Verification Failed",
				`<h1>Invalid Request</h1>

				<p>
					Missing <code>code</code> or <code>state</code>.
					Please start the verification flow again.
				</p>`
			)
		);
	}

	// -------------------------------------------------------------------------
	// Determine whether this is the public Entry Link flow.
	// -------------------------------------------------------------------------

	const stateString = String(state);
	const webState = webOAuthStates.get(stateString);

	let isWebOAuth = false;

	if (webState) {
		webOAuthStates.delete(stateString);

		if (Date.now() - webState.createdAt > 10 * 60 * 1000) {
			return res.status(400).send(
				page(
					"Verification Failed",
					`<h1>Session Expired</h1>

					<p>
						This authentication session has expired.
						Please return to the home page and try again.
					</p>`
				)
			);
		}

		isWebOAuth = true;
	}

	// -------------------------------------------------------------------------
	// Existing Discord OAuth flow.
	//
	// DO NOT CHANGE THE DISCORD FLOW.
	//
	// If this is NOT a public web OAuth state, it MUST contain a valid
	// Discord user ID and nonce generated by the Discord bot.
	// -------------------------------------------------------------------------

	const parsedState = isWebOAuth
		? null
		: parseState(stateString);

	if (!isWebOAuth && !parsedState) {
		return res.status(400).send(
			page(
				"Verification Failed",
				`<h1>Invalid Request</h1>

				<p>
					The verification link has expired or was tampered with.
					Please start again from Discord.
				</p>`
			)
		);
	}

	if (
		!ROBLOX_OAUTH_CLIENT_ID ||
		!ROBLOX_OAUTH_CLIENT_SECRET ||
		!VERIFY_PUBLIC_URL
	) {
		console.warn(
			"[verify] missing ROBLOX_OAUTH_CLIENT_ID/SECRET/VERIFY_PUBLIC_URL"
		);

		return res.status(500).send(
			page(
				"Verification Failed",
				`<h1>Service Misconfigured</h1>

				<p>
					This service is missing required configuration.
					Please contact Conjures staff.
				</p>`
			)
		);
	}

	try {
		// -----------------------------------------------------------------------
		// Exchange authorization code for Roblox access token.
		//
		// This is unchanged for both flows.
		// -----------------------------------------------------------------------

		const tokenBody = new URLSearchParams({
			client_id: ROBLOX_OAUTH_CLIENT_ID,
			client_secret: ROBLOX_OAUTH_CLIENT_SECRET,
			grant_type: "authorization_code",
			code: String(code),
			redirect_uri: redirectUri(),
		});

		const tokenResponse = await fetch(TOKEN_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: tokenBody.toString(),
		});

		if (!tokenResponse.ok) {
			const text2 = await tokenResponse
				.text()
				.catch(() => "");

			console.warn(
				`[verify] token exchange failed ${tokenResponse.status}: ${text2}`
			);

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>Roblox Error</h1>

					<p>
						Couldn't complete authentication with Roblox.
						Please try again.
					</p>`
				)
			);
		}

		const tokenData = await tokenResponse.json();

		if (!tokenData.access_token) {
			console.warn("[verify] Roblox token response did not contain access_token");

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>Roblox Error</h1>

					<p>
						Roblox did not return a valid authentication token.
						Please try again.
					</p>`
				)
			);
		}

		// -----------------------------------------------------------------------
		// Retrieve Roblox profile.
		//
		// The Roblox User ID (sub) is the account identifier.
		// Username/display name are display information.
		// -----------------------------------------------------------------------

		const userResponse = await fetch(USERINFO_URL, {
			headers: {
				Authorization: `Bearer ${tokenData.access_token}`,
			},
		});

		if (!userResponse.ok) {
			console.warn(
				`[verify] userinfo request failed ${userResponse.status}`
			);

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>Roblox Error</h1>

					<p>
						Couldn't read your Roblox profile.
						Please try again.
					</p>`
				)
			);
		}

		const userData = await userResponse.json();

		const robloxUserId = userData.sub;
		const robloxUsername = userData.preferred_username;

		if (!robloxUserId) {
			console.warn("[verify] Roblox userinfo response missing sub");

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>Roblox Error</h1>

					<p>
						Roblox didn't return a valid Roblox User ID.
						Please try again.
					</p>`
				)
			);
		}

		// Username is useful display information, but the Roblox User ID
		// remains the actual account identifier.
		const displayUsername =
			robloxUsername || "your Roblox account";

		// -----------------------------------------------------------------------
		// PUBLIC ENTRY LINK FLOW
		// -----------------------------------------------------------------------
		//
		// IMPORTANT:
		// No Discord ID exists here.
		//
		// Therefore:
		// - no pending_verifications insert
		// - no Discord account association
		// - no role assignment
		// - no nickname update
		// - no bot request
		//
		// This flow ONLY demonstrates successful Roblox authentication.
		// -----------------------------------------------------------------------

		if (isWebOAuth) {
			return res.send(
				page(
					"Roblox Authentication Successful",
					`<span class="badge">Authentication Successful</span>

					<h1>Roblox authentication successful</h1>

					<p>
						You successfully authenticated a Roblox account
						with Conjures Verify.
					</p>

					<p>
						<strong>Roblox Username:</strong>
						${escapeHtml(displayUsername)}
					</p>

					<p>
						This direct entry flow does not link your Roblox
						account to a Discord account and does not create
						a Conjures verification record.
					</p>

					<p>
						The authentication flow has completed successfully.
						You may now close this window.
					</p>`
				)
			);
		}

		// -----------------------------------------------------------------------
		// DISCORD VERIFICATION FLOW
		// -----------------------------------------------------------------------
		//
		// THIS IS THE EXISTING DISCORD VERIFICATION BEHAVIOR.
		//
		// This code ONLY runs when:
		// - the state was NOT a public web state
		// - parseState() successfully recovered the Discord ID + nonce
		//
		// The existing pending_verifications database behavior is preserved.
		// -----------------------------------------------------------------------

		if (pool) {
			await pool.query(
				"insert into pending_verifications (discord_id, roblox_user_id, roblox_username) values ($1, $2, $3)",
				[
					parsedState.discordUserId,
					String(robloxUserId),
					displayUsername,
				]
			);
		} else {
			console.warn(
				"[verify] DATABASE_URL missing - cannot record pending verification"
			);
		}

		return res.send(
			page(
				"Verified",
				`<span class="badge">Success</span>

				<h1>Roblox account linked</h1>

				<p>
					Linked as <strong>${escapeHtml(displayUsername)}</strong>.
					You can close this tab and return to Discord -
					your role and nickname will update within a few seconds.
				</p>`
			)
		);
	} catch (err) {
		console.error("[verify] callback failed -", err);

		return res.status(500).send(
			page(
				"Verification Failed",
				`<h1>Something Went Wrong</h1>

				<p>
					Please try again. If this keeps happening,
					contact Conjures staff.
				</p>`
			)
		);
	}
});

// -----------------------------------------------------------------------------
// Start server
// -----------------------------------------------------------------------------

app.listen(PORT, () => {
	console.log(`[verify] listening on ${PORT}`);
});
