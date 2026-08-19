// verify.conjures.net - standalone OAuth callback + landing service for the
// CONJURES Discord bot's custom Roblox verification system.
//
// There are two OAuth entry paths:
//
// 1. Discord verification:
//    Discord -> Roblox -> /callback -> pending_verifications -> Discord bot
//
// 2. Public OAuth Entry Link:
//    / -> /login -> Roblox -> /callback -> success page only
//
// The public Entry Link flow DOES NOT verify anyone in Conjures, does not
// associate a Discord account, and does not write to pending_verifications.
// It exists so the Roblox OAuth app reviewer can independently test that
// the OAuth application has a working entry and authorization flow.
// Fix

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

// -----------------------------------------------------------------------------
// Public OAuth Entry Link state
// -----------------------------------------------------------------------------
//
// These states are ONLY for:
// https://verify.conjures.net/
//
// They are completely separate from the Discord verification state.
//
// They are:
// - random
// - temporary
// - single-use
// - NOT associated with a Discord ID
// - NEVER inserted into pending_verifications
//
// A Railway restart simply clears these temporary states, which is fine.
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
// This prevents abandoned sessions from remaining in memory forever.
setInterval(() => {
	const expiration = 10 * 60 * 1000;
	const now = Date.now();

	for (const [state, data] of webOAuthStates.entries()) {
		if (now - data.createdAt > expiration) {
			webOAuthStates.delete(state);
		}
	}
}, 60 * 1000);

function page(title, body) {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title} - Conjures Verify</title>
<style>
  :root { color-scheme: dark; }

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
	max-width: 640px;
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

  .badge {
	display: inline-block;
	padding: 4px 10px;
	border-radius: 999px;
	background: rgba(168,139,250,0.15);
	color: #c4b5fd;
	font-size: 0.8rem;
	margin-bottom: 16px;
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

app.get("/", (_req, res) => {
	res.send(
		page(
			"Home",
			`<span class="badge">Roblox Verification</span>

			<h1>Conjures Roblox Verification</h1>

			<p>
				Connect your Roblox account to Conjures using Roblox OAuth.
			</p>

			<p>
				Conjures Verify is used to securely authenticate your Roblox
				account for verification within the Conjures Discord community.
			</p>

			<p style="margin-top: 28px;">
				<a href="/login" style="
					display: inline-block;
					padding: 12px 20px;
					border-radius: 10px;
					background: #a78bfa;
					color: white;
					text-decoration: none;
					font-weight: 600;
				">
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
				and is not affiliated with or endorsed by Roblox.
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
// It does NOT receive a Discord ID.
// It does NOT create a Discord association.
// It does NOT write to pending_verifications.
//
// It simply starts a normal Roblox OAuth authorization request.
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
		scope: "openid profile",
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
				Our privacy policy is simple. Conjures Verify only collects
				and stores the information necessary to provide Roblox
				account verification.
			</p>

			<h2>Information We Collect</h2>

			<ul>
				<li>
					Your Roblox User ID, username, and display name provided
					through Roblox OAuth.
				</li>
				<li>
					Your Discord User ID, provided by the Conjures
					verification system.
				</li>
			</ul>

			<h2>How We Use Your Information</h2>

			<p>
				We use this information to link your Roblox account to your
				Discord account, verify your identity within the Conjures
				community, assign Discord roles, set your Discord nickname,
				and provide related Conjures services.
			</p>

			<h2>What We Don't Collect</h2>

			<p>
				We do not collect or store your Roblox password, Discord
				password, payment information, or authentication credentials.
			</p>

			<h2>Cookies and Tracking</h2>

			<p>
				We do not use long-term cookies, advertising trackers, or
				tracking technologies for advertising purposes.
			</p>

			<h2>Sharing</h2>

			<p>
				We do not sell your information or share it with unrelated
				third parties for advertising or marketing purposes.
				Information may be processed by services necessary to operate
				Conjures Verify, such as Roblox, Discord, hosting, and database
				infrastructure.
			</p>

			<h2>Data Retention</h2>

			<p>
				Your Roblox and Discord account association is stored while
				necessary to provide Conjures verification services. You may
				request that your account association be removed by contacting
				aycuzi.
			</p>

			<h2>Changes</h2>

			<p>
				This Privacy Policy may be updated from time to time.
				Continued use of the Service after changes are published
				constitutes acceptance of the updated policy.
			</p>

			<h2>Contact</h2>

			<p>
				Questions or requests regarding this Privacy Policy may be
				directed to aycuzi.
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
				By using Conjures Verify, you agree to the following terms:
			</p>

			<ul>
				<li>
					You will only use the Service to link a Roblox account
					that you own or are authorized to use.
				</li>

				<li>
					You will not use the Service to violate Roblox's Terms
					of Use, Community Standards, Creator Third-Party App
					Policy, or any other Roblox rules or policies.
				</li>

				<li>
					You will not use the Service to violate Discord's Terms
					of Service, Community Guidelines, or any other Discord
					rules or policies.
				</li>

				<li>
					You will not use the Service to violate any applicable
					laws or regulations.
				</li>

				<li>
					You will not use the Service to violate the terms, rules,
					or policies of any other service used in connection with
					Conjures.
				</li>

				<li>
					You will not attempt to access, link, or use another
					person's Roblox or Discord account without authorization.
				</li>

				<li>
					You will not exploit, abuse, interfere with, or attempt
					to circumvent the security or authentication systems of
					Conjures, Roblox, Discord, or any related service.
				</li>

				<li>
					Conjures staff may unlink or relink accounts when
					reasonably necessary to enforce community rules,
					investigate abuse, correct errors, or maintain the
					Service.
				</li>

				<li>
					Violations of these Terms may result in restriction or
					termination of access to Conjures Verify and may result
					in moderation action within the Conjures Discord
					community or Roblox group.
				</li>

				<li>
					Conjures Verify is an independent third-party service
					and is not operated by, affiliated with, endorsed by,
					or sponsored by Roblox Corporation or Discord Inc.
				</li>

				<li>
					The Service is provided as-is and as-available without
					a guarantee of continuous uptime or error-free operation.
				</li>
			</ul>

			<p>
				These Terms may be updated or changed at any time.
				Continued use of the Service after changes are published
				constitutes acceptance of the updated Terms.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Roblox OAuth Callback
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
					<code>${String(error)}</code>.
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
						Couldn't complete verification with Roblox.
						Please try again.
					</p>`
				)
			);
		}

		const tokenData = await tokenResponse.json();

		// -----------------------------------------------------------------------
		// Retrieve Roblox profile.
		// -----------------------------------------------------------------------

		const userResponse = await fetch(USERINFO_URL, {
			headers: {
				Authorization: `Bearer ${tokenData.access_token}`,
			},
		});

		if (!userResponse.ok) {
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

		if (!robloxUserId || !robloxUsername) {
			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>Roblox Error</h1>

					<p>
						Roblox didn't return a valid profile.
						Please try again.
					</p>`
				)
			);
		}

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
		// The user has ONLY authenticated with Roblox.
		// -----------------------------------------------------------------------

		if (isWebOAuth) {
			return res.send(
				page(
					"Successfully Authenticated",
					`<span class="badge">Success</span>

					<h1>Successfully authenticated</h1>

					<p>
						Your Roblox account has been successfully
						authenticated with Conjures.
					</p>

					<p>
						<strong>Roblox Username:</strong>
						${robloxUsername}
					</p>

					<p>
						Your Roblox account has been authenticated
						successfully. No Discord account has been linked
						through this public entry flow.
					</p>

					<p style="margin-top: 24px;">
						You may now close this window.
					</p>`
				)
			);
		}

		// -----------------------------------------------------------------------
		// DISCORD VERIFICATION FLOW
		// -----------------------------------------------------------------------
		//
		// This is the existing Conjures verification behavior.
		//
		// This code ONLY runs when:
		// - the state was NOT a public web state
		// - parseState() successfully recovered the Discord ID + nonce
		//
		// This is the ONLY place in this service that writes to
		// pending_verifications.
		// -----------------------------------------------------------------------

		if (pool) {
			await pool.query(
				"insert into pending_verifications (discord_id, roblox_user_id, roblox_username) values ($1, $2, $3)",
				[
					parsedState.discordUserId,
					String(robloxUserId),
					robloxUsername,
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
					Linked as <strong>${robloxUsername}</strong>.
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
