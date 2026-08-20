// verify.conjures.net - standalone OAuth callback + landing service for the
// CONJURES Discord bot's custom Roblox account-linking system.
//
// OAuth entry paths:
//
// 1. Discord verification:
//    Discord -> Roblox -> /callback -> pending_verifications -> Discord bot
//
// 2. Public OAuth Entry Link:
//    / -> /login -> Roblox -> /callback -> public success page
//
// 3. Data deletion request:
//    / -> /delete-data -> Roblox -> /callback -> deletion request page
//
// IMPORTANT:
//
// - All Roblox OAuth flows request ONLY:
//     "openid profile"
//
// - The public Entry Link flow does NOT receive a Discord ID.
// - The public Entry Link flow does NOT create a Discord/Roblox association.
// - The public Entry Link flow does NOT write to pending_verifications.
// - The public Entry Link flow does NOT assign Discord roles or nicknames.
//
// - The Data Deletion flow is completely separate from Discord verification.
// - The Data Deletion flow does NOT write to pending_verifications.
// - The Data Deletion flow does NOT write to verifications.
// - The Data Deletion flow does NOT modify Discord roles.
// - The Data Deletion flow does NOT modify Discord nicknames.
// - The Data Deletion flow does NOT delete database records.
//
// The deletion flow only records a temporary in-memory deletion request.
// Temporary deletion requests expire automatically after 5 minutes.
//
// Roblox account identity is based on the Roblox OAuth "sub" value
// (Roblox User ID). Username/display name are display information only.

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
// This function is intentionally compatible with the existing Discord
// verification flow.
//
// The Discord bot creates this state and the callback uses it to recover the
// Discord user ID.
//
// Do not change the Discord OAuth initiation flow in this function.
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
// These states are ONLY for:
//
// https://verify.conjures.net/
//
// They are:
//
// - cryptographically random
// - temporary
// - single-use
// - NOT associated with a Discord ID
// - NEVER inserted into pending_verifications
// - NEVER used to assign Discord roles
// - NEVER used to change Discord nicknames
//
// -----------------------------------------------------------------------------

const webOAuthStates = new Map();

function createWebOAuthState() {
	const state = crypto.randomBytes(32).toString("base64url");

	webOAuthStates.set(state, {
		createdAt: Date.now(),
	});

	return state;
}

// -----------------------------------------------------------------------------
// Data Deletion OAuth state
// -----------------------------------------------------------------------------
//
// This is completely separate from:
//
// - Discord OAuth state
// - public Entry Link OAuth state
//
// A deletion OAuth state only means:
//
// "This Roblox OAuth session is being used to identify the Roblox account
// for a data deletion request."
//
// It is NOT a Discord verification state.
//
// It does NOT write to pending_verifications.
// It does NOT write to verifications.
// -----------------------------------------------------------------------------

const deletionOAuthStates = new Map();

function createDeletionOAuthState() {
	const state = crypto.randomBytes(32).toString("base64url");

	deletionOAuthStates.set(state, {
		createdAt: Date.now(),
	});

	return state;
}

// -----------------------------------------------------------------------------
// Temporary deletion requests
// -----------------------------------------------------------------------------
//
// These requests are intentionally kept only in server memory.
//
// They are NOT stored in PostgreSQL.
//
// They do NOT modify:
// - pending_verifications
// - verifications
//
// They automatically expire after 5 minutes.
//
// -----------------------------------------------------------------------------

const deletionRequests = new Map();

function createDeletionRequest({
	robloxUserId,
	robloxUsername,
}) {
	const requestId = crypto.randomBytes(24).toString("base64url");

	deletionRequests.set(requestId, {
		requestId,
		robloxUserId: String(robloxUserId),
		robloxUsername: robloxUsername || "Unknown Roblox user",
		createdAt: Date.now(),
	});

	return requestId;
}

// -----------------------------------------------------------------------------
// Clean up temporary public OAuth states, deletion OAuth states, and deletion
// requests.
//
// Nothing here touches the database.
// -----------------------------------------------------------------------------

setInterval(() => {
	const expiration = 10 * 60 * 1000;
	const requestExpiration = 5 * 60 * 1000;
	const now = Date.now();

	// Public OAuth states
	for (const [state, data] of webOAuthStates.entries()) {
		if (now - data.createdAt > expiration) {
			webOAuthStates.delete(state);
		}
	}

	// Deletion OAuth states
	for (const [state, data] of deletionOAuthStates.entries()) {
		if (now - data.createdAt > expiration) {
			deletionOAuthStates.delete(state);
		}
	}

	// Temporary deletion requests
	for (const [requestId, request] of deletionRequests.entries()) {
		if (now - request.createdAt > requestExpiration) {
			deletionRequests.delete(requestId);
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
<meta
	name="description"
	content="Conjures Roblox account linking service."
/>
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

  p,
  li {
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
	border: 0;
	cursor: pointer;
	font-size: 0.95rem;
  }

  .button:hover {
	background: #8b5cf6;
  }

  .button-danger {
	background: #dc5a6b;
  }

  .button-danger:hover {
	background: #c74759;
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

  .notice {
	margin-top: 20px;
	padding: 16px;
	border-radius: 10px;
	background: rgba(255,255,255,0.04);
	border: 1px solid rgba(255,255,255,0.08);
  }

  .footer {
	margin-top: 32px;
	font-size: 0.8rem;
	color: #6b7086;
  }

  .footer a {
	color: #8b90a8;
  }

  .divider {
	margin: 28px 0;
	border: 0;
	border-top: 1px solid rgba(255,255,255,0.08);
  }

  .danger-box {
	margin-top: 24px;
	padding: 18px;
	border-radius: 10px;
	background: rgba(220,90,107,0.08);
	border: 1px solid rgba(220,90,107,0.18);
  }

  .danger-box strong {
	color: #fda4af;
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
// Public Home
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

			<p style="margin-top: 16px;">
				<a href="/delete-data" class="button button-danger">
					Delete Data
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
// Existing public Entry Link flow.
//
// Does NOT receive a Discord ID.
// Does NOT create an association.
// Does NOT write to pending_verifications.
// Does NOT write to verifications.
//
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
// Data Deletion OAuth Login
// -----------------------------------------------------------------------------
//
// IMPORTANT:
//
// This is a completely separate OAuth flow.
//
// It does NOT:
//
// - receive a Discord ID
// - call the Discord bot
// - write pending_verifications
// - write verifications
// - modify existing verification records
//
// It ONLY authenticates the Roblox account so that the deletion request
// can be associated with the authenticated Roblox User ID.
// -----------------------------------------------------------------------------

app.get("/delete-data", (_req, res) => {
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

	return res.send(
		page(
			"Delete Data",
			`<span class="badge">Data Management</span>

			<h1>Delete Your Data</h1>

			<p>
				To submit a data deletion, first authenticate
				with the Roblox account associated with your Conjures
				account.
			</p>

			<p>
				This allows us to identify the Roblox account for which
				the request is being made without requiring you to
				provide your Roblox User ID manually.
			</p>

			<div class="scope-box">
				<strong>Roblox authentication</strong>

				<p style="margin-bottom: 0;">
					Only the <code>openid</code> and <code>profile</code>
					scopes are requested.
				</p>
			</div>

			<p style="margin-top: 28px;">
				<a href="/delete-data/login" class="button button-danger">
					Continue with Roblox
				</a>
			</p>

			<p style="font-size: 0.85rem; margin-top: 20px;">
				Your authentication is used only to identify the Roblox
				account associated with this request.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Start Data Deletion OAuth
// -----------------------------------------------------------------------------

app.get("/delete-data/login", (_req, res) => {
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

	const state = createDeletionOAuthState();

	const params = new URLSearchParams({
		client_id: ROBLOX_OAUTH_CLIENT_ID,
		redirect_uri: redirectUri(),

		// Keep deletion flow within the same minimum OAuth permissions.
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
				This will include:
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

				<li>
					Processing data management and deletion requests.
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
				You may request deletion of your Roblox and Discord
				account-linking information through the
				<strong>Delete Data</strong> option available on the
				Conjures Verify website.
			</p>

			<p>
				The deletion request process uses Roblox OAuth to identify
				the Roblox account associated with the request. You may
				also contact Conjures staff regarding a data deletion
				request at any time.
			</p>

			<p>
				Deletion requests are handled by our system automatically and
				Conjures staff and may require additional verification where 
				reasonably necessary to protect account security.
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

			<h2>8. Data Deletion Requests</h2>

			<p>
				Users may submit a request concerning deletion of their
				Roblox and Discord account-linking information through
				the Delete Data option on Conjures Verify or by contacting
				Conjures staff.
			</p>

			<p>
				Requests may require authentication through Roblox OAuth
				or additional verification to ensure that the request
				concerns the appropriate account.
			</p>

			<h2>9. Privacy</h2>

			<p>
				Your use of Conjures Verify is also governed by our
				Privacy Policy, which explains what information we
				collect, how we use it, how it is retained, and how
				you may request its removal.
			</p>

			<h2>10. Third-Party Services</h2>

			<p>
				Conjures Verify interacts with third-party services,
				including Roblox and Discord. Your use of those services
				is also subject to their respective terms, policies,
				and requirements.
			</p>

			<h2>11. Relationship With Roblox</h2>

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

			<h2>12. Relationship With Discord</h2>

			<p>
				Conjures Verify is also independent from Discord Inc.
				and is not affiliated with, endorsed by, sponsored by,
				or operated by Discord Inc.
			</p>

			<h2>13. Service Availability</h2>

			<p>
				Conjures Verify is provided on an as-is and as-available
				basis. We do not guarantee that the service will always
				be available, uninterrupted, or error-free.
			</p>

			<h2>14. Changes to These Terms</h2>

			<p>
				These Terms of Service may be updated from time to time.
				When changes are made, the updated Terms will be published
				on this page with a new effective date.
			</p>

			<p>
				Your continued use of Conjures Verify after updated Terms
				are published constitutes acceptance of the updated Terms.
			</p>

			<h2>15. Contact</h2>

			<p>
				Questions regarding these Terms of Service may be directed
				to Conjures staff.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Submit temporary deletion request
// -----------------------------------------------------------------------------
//
// IMPORTANT:
//
// This endpoint ONLY creates a temporary in-memory request.
//
// It does NOT:
//
// - DELETE from pending_verifications
// - DELETE from verifications
// - UPDATE pending_verifications
// - UPDATE verifications
// - modify Discord
//
// -----------------------------------------------------------------------------

app.post("/delete-data/request", express.urlencoded({ extended: false }), (req, res) => {
	const requestId = String(req.body.request_id || "");

	const request = deletionRequests.get(requestId);

	if (!request) {
		return res.status(400).send(
			page(
				"Request Expired",
				`<h1>Request Expired</h1>

				<p>
					This deletion request session has expired.
					Please start again from the Delete Data page.
				</p>`
			)
		);
	}

	// Mark this temporary request as submitted.
	request.submittedAt = Date.now();

	// Keep it temporarily available so the confirmation can be displayed.
	deletionRequests.set(requestId, request);

	return res.send(
		page(
			"Data Deletion Submitted",
			`<span class="badge">Request Submitted</span>

			<h1>Deletion Request Submitted</h1>

			<p>
				Your data deletion request has been received for the
				authenticated Roblox account.
			</p>

			<p>
				<strong>Roblox Username:</strong>
				${escapeHtml(request.robloxUsername)}
			</p>

			<div class="notice">
				<p style="margin: 0;">
					Your request has been recorded for processing 
					which will be handled immediately and will
					erase all data.
				</p>
			</div>

			<p style="margin-top: 24px;">
				If you have additional questions about your account
				or data, please contact Conjures staff.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Roblox OAuth Callback
// -----------------------------------------------------------------------------
//
// There are now THREE possible callback states:
//
// 1. deletionOAuthStates
//      -> deletion flow
//
// 2. webOAuthStates
//      -> public reviewer/public Entry Link flow
//
// 3. parseState(state)
//      -> Discord verification flow
//
// The order is deliberate.
//
// Deletion state is checked FIRST.
//
// This guarantees that a deletion request can never accidentally fall through
// into the Discord verification branch.
//
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

	const stateString = String(state);

	// -------------------------------------------------------------------------
	// Determine deletion flow
	// -------------------------------------------------------------------------

	const deletionState = deletionOAuthStates.get(stateString);

	let isDeletionOAuth = false;

	if (deletionState) {
		deletionOAuthStates.delete(stateString);

		if (Date.now() - deletionState.createdAt > 10 * 60 * 1000) {
			return res.status(400).send(
				page(
					"Request Expired",
					`<h1>Session Expired</h1>

					<p>
						This authentication session has expired.
						Please return to the Delete Data page and try again.
					</p>`
				)
			);
		}

		isDeletionOAuth = true;
	}

	// -------------------------------------------------------------------------
	// Determine public Entry Link flow
	// -------------------------------------------------------------------------

	const webState = isDeletionOAuth
		? null
		: webOAuthStates.get(stateString);

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
	// Existing Discord OAuth flow
	// -------------------------------------------------------------------------
	//
	// IMPORTANT:
	//
	// This only executes if the state wasn't generated for either:
	//
	// - deletion OAuth
	// - public web OAuth
	//
	// The existing Discord state parser remains unchanged.
	// -------------------------------------------------------------------------

	const parsedState =
		isDeletionOAuth || isWebOAuth
			? null
			: parseState(stateString);

	if (!isDeletionOAuth && !isWebOAuth && !parsedState) {
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
						Couldn't complete authentication with Roblox.
						Please try again.
					</p>`
				)
			);
		}

		const tokenData = await tokenResponse.json();

		if (!tokenData.access_token) {
			console.warn(
				"[verify] Roblox token response did not contain access_token"
			);

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

		// Roblox documents "sub" as the stable Roblox User ID.
		const robloxUserId = userData.sub;
		const robloxUsername =
			userData.preferred_username;

		if (!robloxUserId) {
			console.warn(
				"[verify] Roblox userinfo response missing sub"
			);

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

		const displayUsername =
			robloxUsername || "your Roblox account";

		// -----------------------------------------------------------------------
		// DATA DELETION FLOW
		// -----------------------------------------------------------------------
		//
		// IMPORTANT:
		//
		// Nothing below touches PostgreSQL.
		//
		// In particular, this flow NEVER executes:
		//
		//   INSERT INTO pending_verifications
		//
		// and NEVER executes:
		//
		//   DELETE FROM pending_verifications
		//
		// and NEVER touches "verifications".
		//
		// -----------------------------------------------------------------------

		if (isDeletionOAuth) {
			const requestId = createDeletionRequest({
				robloxUserId,
				robloxUsername: displayUsername,
			});

			return res.send(
				page(
					"Delete Data",
					`<span class="badge">Data Management</span>

					<h1>Delete Your Data</h1>

					<p>
						You are authenticated as:
					</p>

					<div class="notice">
						<p style="margin: 0;">
							<strong>Roblox Username:</strong>
							${escapeHtml(displayUsername)}
						</p>
					</div>

					<p style="margin-top: 24px;">
						If you want to request deletion of the data
						associated with this Roblox account, submit the
						request below.
					</p>

					<div class="danger-box">
						<strong>Important</strong>

						<p style="margin-bottom: 0;">
							Submitting this request will proceed
							to process the deletion of data associated
							with this account.
						</p>
					</div>

					<form
						method="POST"
						action="/delete-data/request"
						style="margin-top: 28px;"
					>
						<input
							type="hidden"
							name="request_id"
							value="${escapeHtml(requestId)}"
						/>

						<button
							type="submit"
							class="button button-danger"
						>
							Submit Data Deletion Request
						</button>
					</form>

					<p style="font-size: 0.85rem; margin-top: 20px;">
						This request is associated with your authenticated
						Roblox account.
					</p>`
				)
			);
		}

		// -----------------------------------------------------------------------
		// PUBLIC ENTRY LINK FLOW
		// -----------------------------------------------------------------------
		//
		// No Discord ID.
		// No database write.
		// No association.
		//
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
		// DO NOT CHANGE.
		//
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
					Linked as
					<strong>${escapeHtml(displayUsername)}</strong>.
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
