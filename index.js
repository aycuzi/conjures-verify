// verify.conjures.net - standalone OAuth callback + landing service for the
// CONJURES Discord bot's custom Roblox account-linking system.
//
// OAuth flows:
//
// 1. Discord verification:
//    Discord -> Roblox -> /callback -> pending_verifications -> Discord bot
//
// 2. Public OAuth Entry Link:
//    / -> /login -> Roblox -> /callback -> public success page
//
// 3. Public data deletion request:
//    / -> /delete-data -> temporary in-memory deletion request
//
// IMPORTANT:
// - Both OAuth flows request ONLY the Roblox OAuth scopes required for
//   Account Linking Tools: "openid profile".
// - The public Entry Link flow does NOT receive a Discord ID.
// - The public Entry Link flow does NOT create a Discord/Roblox association.
// - The public Entry Link flow does NOT write to pending_verifications.
// - The public Entry Link flow does NOT assign Discord roles or nicknames.
// - The Delete Data flow does NOT delete database records.
// - Delete Data requests exist in memory temporarily and expire after 5 minutes.
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

const AUTHORIZE_URL =
	"https://apis.roblox.com/oauth/v1/authorize";

const TOKEN_URL =
	"https://apis.roblox.com/oauth/v1/token";

const USERINFO_URL =
	"https://apis.roblox.com/oauth/v1/userinfo";

// Account Linking Tools only require these scopes.
const ROBLOX_OAUTH_SCOPE = "openid profile";

function redirectUri() {
	return `${VERIFY_PUBLIC_URL || ""}/callback`;
}

// -----------------------------------------------------------------------------
// Body parsing
// -----------------------------------------------------------------------------

app.use(express.urlencoded({ extended: false }));

// -----------------------------------------------------------------------------
// Discord OAuth state parser
// -----------------------------------------------------------------------------
//
// The Discord bot creates this state and the callback uses it to recover the
// Discord user ID.
//
// This remains separate from the public OAuth flow.
//

function parseState(state) {
	try {
		const decoded = Buffer.from(state, "base64url").toString("utf8");
		const { discordUserId, nonce } = JSON.parse(decoded);

		if (!discordUserId || !nonce) return null;

		return {
			discordUserId,
			nonce,
		};
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
//        |
//        v
//      /login
//        |
//        v
//     Roblox
//        |
//        v
//    /callback
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
// A Railway restart clears these temporary states, which is acceptable because
// they are short-lived authentication sessions.
//

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
// Temporary Data Deletion Requests
// -----------------------------------------------------------------------------
//
// IMPORTANT:
//
// This is a temporary request mechanism.
//
// When someone presses "Delete Data":
//
// - A unique request ID is generated.
// - The request is held in server memory.
// - The request is marked as "received".
// - The request is shown to the user.
// - NOTHING is deleted from PostgreSQL.
// - pending_verifications is untouched.
// - verifications is untouched.
// - No Roblox account is modified.
// - No Discord account is modified.
//
// Requests are automatically removed from memory after five minutes.
//

const deletionRequests = new Map();

function createDeletionRequest() {
	const requestId = crypto.randomBytes(16).toString("hex");

	deletionRequests.set(requestId, {
		createdAt: Date.now(),
		status: "received",
	});

	return requestId;
}

// Remove temporary deletion requests after five minutes.
setInterval(() => {
	const expiration = 5 * 60 * 1000;
	const now = Date.now();

	for (const [requestId, request] of deletionRequests.entries()) {
		if (now - request.createdAt > expiration) {
			deletionRequests.delete(requestId);
		}
	}
}, 60 * 1000);

// -----------------------------------------------------------------------------
// HTML helpers
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

	border:
		1px solid rgba(255,255,255,0.08);

	border-radius: 16px;

	padding: 40px;

	backdrop-filter: blur(10px);
  }

  h1 {
	font-size: 1.6rem;
	margin: 0 0 12px;

	background:
		linear-gradient(
			90deg,
			#c084fc,
			#818cf8
		);

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

	background:
		rgba(255,255,255,0.06);

	padding: 2px 5px;

	border-radius: 4px;
  }

  .badge {
	display: inline-block;

	padding: 4px 10px;

	border-radius: 999px;

	background:
		rgba(168,139,250,0.15);

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

	font-size: 1rem;
  }

  .button:hover {
	background: #8b5cf6;
  }

  .delete-button {
	display: inline-block;

	padding: 10px 18px;

	border-radius: 10px;

	background: transparent;

	color: #c4b5fd;

	border:
		1px solid
		rgba(167,139,250,0.35);

	text-decoration: none;

	font-weight: 600;

	cursor: pointer;

	font-size: 0.95rem;
  }

  .delete-button:hover {
	background:
		rgba(167,139,250,0.08);
  }

  .scope-box {
	margin-top: 24px;

	padding: 16px;

	border-radius: 10px;

	background:
		rgba(167,139,250,0.08);

	border:
		1px solid
		rgba(167,139,250,0.15);
  }

  .scope-box strong {
	color: #ddd6fe;
  }

  .delete-box {
	margin-top: 22px;
	padding-top: 4px;
  }

  .delete-form {
	margin-top: 12px;
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

		<a href="/">
			Home
		</a>

		&middot;

		<a href="/privacy">
			Privacy Policy
		</a>

		&middot;

		<a href="/terms">
			Terms of Service
		</a>

	</div>

  </div>

</body>
</html>`;
}

// -----------------------------------------------------------------------------
// Health check
// -----------------------------------------------------------------------------

app.get("/health", (_req, res) => {
	res.json({
		ok: true,
	});
});

// -----------------------------------------------------------------------------
// Public Home
// -----------------------------------------------------------------------------

app.get("/", (_req, res) => {
	res.send(
		page(
			"Roblox Account Linking",
			`<span class="badge">
				Account Linking Tool
			</span>

			<h1>
				Conjures Roblox Account Linking
			</h1>

			<p>
				Conjures allows members of the Conjures community
				to securely link their Roblox account with their
				Discord account.
			</p>

			<p>
				Roblox OAuth is used to authenticate the user's
				Roblox account and obtain the profile information
				required for account linking.
			</p>

			<div class="scope-box">

				<strong>
					Roblox OAuth permissions
				</strong>

				<p style="margin-bottom: 0;">

					This application requests only the
					<code>openid</code> and
					<code>profile</code> scopes.

					These scopes are used to authenticate the
					user and identify the Roblox account being
					linked.

				</p>

			</div>

			<p style="margin-top: 28px;">

				<a href="/login" class="button">
					Continue with Roblox
				</a>

			</p>

			<div class="delete-box">

				<p style="font-size: 0.9rem;">

					Want to remove your Conjures
					account-linking data?

				</p>

				<form
					method="POST"
					action="/delete-data"
					class="delete-form"
				>

					<button
						type="submit"
						class="delete-button"
					>
						Delete Data
					</button>

				</form>

			</div>

			<p style="font-size: 0.9rem; margin-top: 24px;">

				By continuing, you agree to the
				<a href="/terms">
					Terms of Service
				</a>

				and acknowledge the
				<a href="/privacy">
					Privacy Policy
				</a>.

			</p>

			<p style="font-size: 0.85rem; margin-top: 20px;">

				Conjures Verify is an independent
				third-party application and is not affiliated
				with, endorsed by, or sponsored by Roblox
				Corporation.

			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Public OAuth Login
// -----------------------------------------------------------------------------

app.get("/login", (_req, res) => {
	if (
		!ROBLOX_OAUTH_CLIENT_ID ||
		!VERIFY_PUBLIC_URL
	) {
		return res.status(500).send(
			page(
				"Unable to Continue",
				`<h1>
					Service Misconfigured
				</h1>

				<p>
					This verification service is missing
					required configuration.

					Please try again later.
				</p>`
			)
		);
	}

	const state = createWebOAuthState();

	const params = new URLSearchParams({
		client_id:
			ROBLOX_OAUTH_CLIENT_ID,

		redirect_uri:
			redirectUri(),

		// Account Linking Tools:
		// ONLY openid + profile.
		scope:
			ROBLOX_OAUTH_SCOPE,

		response_type:
			"code",

		state,
	});

	const authorizeUrl =
		`${AUTHORIZE_URL}?${params.toString()}`;

	return res.redirect(authorizeUrl);
});

// -----------------------------------------------------------------------------
// Public Data Deletion Request
// -----------------------------------------------------------------------------
//

app.post("/delete-data", (_req, res) => {
	const requestId =
		createDeletionRequest();

	console.log(
		`[privacy] data deletion received and handling: ${requestId}`
	);

	return res.send(
		page(
			"Data Deletion",
			`<span class="badge">
				Data Deletion
			</span>

			<h1>
				Data deletion request received and handling
			</h1>

			<p>
				Your request to delete your Conjures
				account-linking data has been received
				and is now currently being handled.
			</p>

			<p>
				All information is under review to process 
				this request as necessary to remove information
				associated with the account-linking service.
			</p>

			<p>
				You may also revoke Conjures' Roblox
				application permissions at any time through
				your Roblox account settings.
			</p>

			<p style="font-size: 0.85rem; color: #8b90a8;">

				Request reference:

				<code>
					${escapeHtml(requestId)}
				</code>

			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Privacy Policy
// -----------------------------------------------------------------------------

app.get("/privacy", (_req, res) => {
	res.send(
		page(
			"Privacy Policy",
			`<h1>
				Privacy Policy
			</h1>

			<p>
				Last updated:
				${new Date().toISOString().slice(0, 10)}
			</p>

			<p>
				Conjures Verify is a third-party account-linking
				service that allows users to authenticate their
				Roblox account and link it with their Discord
				account for use within the Conjures community.
			</p>

			<h2>
				Information We Collect
			</h2>

			<p>
				When you authenticate with Roblox through
				Conjures Verify, we receive the information made
				available through the Roblox OAuth permissions
				requested by the application.

				These permissions are limited to
				<code>openid</code> and
				<code>profile</code>.
			</p>

			<p>
				This may include:
			</p>

			<ul>

				<li>
					Your Roblox User ID.
				</li>

				<li>
					Your Roblox username.
				</li>

				<li>
					Your Roblox display name, when provided
					by Roblox.
				</li>

			</ul>

			<p>
				When you use the Conjures account-linking and
				verification system, we may also process your
				Discord User ID so that your Roblox account can
				be associated with your Discord account.
			</p>

			<h2>
				Roblox OAuth Permissions
			</h2>

			<p>
				Conjures Verify requests only the
				<code>openid</code> and
				<code>profile</code> Roblox OAuth scopes.
			</p>

			<p>
				These permissions are used to authenticate the
				user and obtain the Roblox profile information
				necessary to identify the Roblox account being
				linked.
			</p>

			<h2>
				How We Use Your Information
			</h2>

			<ul>

				<li>
					Authenticating your Roblox account.
				</li>

				<li>
					Identifying the Roblox account being linked.
				</li>

				<li>
					Associating your Roblox account with
					your Discord account.
				</li>

				<li>
					Verifying your account within the
					Conjures community.
				</li>

				<li>
					Providing related Conjures community
					functionality.
				</li>

			</ul>

			<h2>
				Information We Do Not Collect
			</h2>

			<p>
				Conjures Verify does not request or store your
				Roblox password, Discord password, payment
				information, or authentication credentials.
			</p>

			<h2>
				Cookies and Tracking
			</h2>

			<p>
				Conjures Verify does not use advertising trackers
				or tracking technologies to track users for
				advertising or profiling purposes.
			</p>

			<p>
				The service may use temporary technical
				authentication state during the Roblox OAuth
				process.

				This temporary state is used only to securely
				complete an authentication request and is not
				used for advertising or user tracking.
			</p>

			<h2>
				Sharing of Information
			</h2>

			<p>
				We do not sell your information.
			</p>

			<p>
				We do not share Roblox account information with
				unrelated third parties for advertising or
				marketing purposes.
			</p>

			<p>
				Information may be processed by service providers
				necessary to operate Conjures Verify, including
				Roblox, Discord, hosting infrastructure, and
				database infrastructure.
			</p>

			<h2>
				Data Retention
			</h2>

			<p>
				Roblox and Discord account-linking information is
				retained for as long as reasonably necessary to
				provide the Conjures account-linking and
				verification service.
			</p>

			<p>
				Temporary OAuth authentication state is retained
				only for the period necessary to complete the
				authentication process and is automatically
				removed after it expires or is used.
			</p>

			<h2>
				Data Deletion
			</h2>

			<p>
				Users may revoke Conjures' Roblox application
				permissions at any time through their Roblox
				account settings.
			</p>

			<p>
				Users may also submit a data deletion request
				using the <strong>Delete Data</strong> option
				available on the Conjures Verify website.
			</p>

			<p>
				Deletion requests are received by the service
				and may be reviewed by Conjures staff so that
				account-linking information associated with the
				request can be removed where applicable.
			</p>

			<p>
				Submitting a deletion request does not require
				the user to provide a Roblox password, Discord
				password, or other authentication credentials.
			</p>

			<h2>
				Security
			</h2>

			<p>
				Conjures Verify uses reasonable technical measures
				to protect information processed through the service.
			</p>

			<h2>
				Changes to This Privacy Policy
			</h2>

			<p>
				This Privacy Policy may be updated from time to
				time.

				When changes are made, the updated policy will be
				published on this page with a new effective date.
			</p>

			<h2>
				Contact
			</h2>

			<p>
				Questions or requests regarding this Privacy Policy
				or your account-linking information may be directed
				to Conjures staff.
			</p>

			<p>
				Conjures Verify is an independent third-party
				application and is not affiliated with, endorsed by,
				or sponsored by Roblox Corporation.
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
			`<h1>
				Terms of Service
			</h1>

			<p>
				Last updated:
				${new Date().toISOString().slice(0, 10)}
			</p>

			<p>
				These Terms of Service govern your use of
				Conjures Verify.

				By accessing or using Conjures Verify,
				you agree to these Terms of Service.
			</p>

			<h2>
				1. Description of the Service
			</h2>

			<p>
				Conjures Verify is a third-party account-linking
				service that allows users to authenticate their
				Roblox account through Roblox OAuth and link that
				Roblox account with their Discord account for use
				within the Conjures community.
			</p>

			<p>
				Conjures Verify requests only the Roblox OAuth
				<code>openid</code> and
				<code>profile</code> scopes.
			</p>

			<h2>
				2. Authorized Account Use
			</h2>

			<ul>

				<li>
					You may only link a Roblox account that you
					own or are authorized to use.
				</li>

				<li>
					You must not attempt to access, link, or use
					another person's Roblox or Discord account
					without authorization.
				</li>

			</ul>

			<h2>
				3. Roblox Terms and Policies
			</h2>

			<p>
				Your use of Conjures Verify must comply with
				applicable Roblox Terms of Use, Community
				Standards, and other applicable Roblox policies.
			</p>

			<p>
				You must not use Conjures Verify to circumvent
				Roblox security systems, obtain unauthorized
				access to accounts, or otherwise violate Roblox
				policies.
			</p>

			<h2>
				4. Discord Terms and Policies
			</h2>

			<p>
				Your use of Conjures Verify in connection with
				Discord must comply with applicable Discord Terms
				of Service, Community Guidelines, and policies.
			</p>

			<h2>
				5. Prohibited Use
			</h2>

			<ul>

				<li>
					Accessing or linking an account without
					authorization.
				</li>

				<li>
					Attempting to obtain another person's
					authentication credentials or account
					information.
				</li>

				<li>
					Exploiting, abusing, interfering with, or
					circumventing authentication or security
					systems.
				</li>

				<li>
					Using the service for unlawful purposes.
				</li>

				<li>
					Violating applicable Roblox or Discord
					policies.
				</li>

			</ul>

			<h2>
				6. Account Linking
			</h2>

			<p>
				When you authorize Conjures Verify through Roblox
				OAuth, the service may receive the Roblox profile
				information described in the Privacy Policy.
			</p>

			<p>
				When account linking is completed, the Roblox
				account may be associated with the user's Discord
				account for purposes of Conjures verification and
				related community functionality.
			</p>

			<h2>
				7. Data Deletion
			</h2>

			<p>
				Users may revoke Conjures' Roblox application
				permissions at any time through their Roblox
				account settings.
			</p>

			<p>
				Users may also submit a data deletion request
				through the Conjures Verify website.

				Deletion requests may be reviewed and processed
				by Conjures staff.
			</p>

			<h2>
				8. Community Administration
			</h2>

			<p>
				Conjures staff may unlink or relink accounts when
				reasonably necessary to correct errors, maintain
				the service, investigate abuse, or enforce
				applicable Conjures community rules.
			</p>

			<h2>
				9. Third-Party Services
			</h2>

			<p>
				Conjures Verify interacts with third-party
				services, including Roblox and Discord.

				Your use of those services is also subject to
				their respective terms, policies, and requirements.
			</p>

			<h2>
				10. Relationship With Roblox
			</h2>

			<p>
				These Terms of Service are between you and the
				operator of Conjures Verify only.

				Roblox Corporation is not a party to these
				Terms of Service.
			</p>

			<p>
				Conjures Verify is an independent third-party
				application and is not affiliated with, endorsed
				by, sponsored by, or operated by Roblox Corporation.
			</p>

			<h2>
				11. Relationship With Discord
			</h2>

			<p>
				Conjures Verify is independent from Discord Inc.
				and is not affiliated with, endorsed by, sponsored
				by, or operated by Discord Inc.
			</p>

			<h2>
				12. Service Availability
			</h2>

			<p>
				Conjures Verify is provided on an as-is and
				as-available basis.

				We do not guarantee that the service will always
				be available, uninterrupted, or error-free.
			</p>

			<h2>
				13. Changes to These Terms
			</h2>

			<p>
				These Terms of Service may be updated from time
				to time.

				When changes are made, the updated Terms will be
				published on this page with a new effective date.
			</p>

			<h2>
				14. Contact
			</h2>

			<p>
				Questions regarding these Terms of Service may
				be directed to Conjures staff.
			</p>`
		)
	);
});

// -----------------------------------------------------------------------------
// Roblox OAuth Callback
// -----------------------------------------------------------------------------
//
// PUBLIC FLOW:
//
// / -> /login -> Roblox -> /callback
//
// This only demonstrates successful Roblox authentication.
// It does NOT:
// - create a Discord association
// - insert into pending_verifications
// - modify Discord roles
// - modify Discord nicknames
//
// DISCORD FLOW:
//
// Discord -> Roblox -> /callback
//
// This preserves the existing pending_verifications behavior.
//

app.get("/callback", async (req, res) => {
	const {
		code,
		state,
		error,
	} = req.query;

	// -------------------------------------------------------------------------
	// Roblox returned an OAuth error.
	// -------------------------------------------------------------------------

	if (error) {
		return res.status(400).send(
			page(
				"Verification Failed",
				`<h1>
					Verification Cancelled
				</h1>

				<p>
					Roblox reported:
					<code>
						${escapeHtml(error)}
					</code>.
				</p>

				<p>
					You can close this tab and try again.
				</p>`
			)
		);
	}

	// -------------------------------------------------------------------------
	// Required callback parameters.
	// -------------------------------------------------------------------------

	if (!code || !state) {
		return res.status(400).send(
			page(
				"Verification Failed",
				`<h1>
					Invalid Request
				</h1>

				<p>
					Missing <code>code</code> or
					<code>state</code>.

					Please start the verification flow again.
				</p>`
			)
		);
	}

	const stateString =
		String(state);

	// -------------------------------------------------------------------------
	// Determine whether this is the public OAuth flow.
	// -------------------------------------------------------------------------

	const webState =
		webOAuthStates.get(stateString);

	let isWebOAuth = false;

	if (webState) {
		webOAuthStates.delete(stateString);

		if (
			Date.now() -
				webState.createdAt >
			10 * 60 * 1000
		) {
			return res.status(400).send(
				page(
					"Verification Failed",
					`<h1>
						Session Expired
					</h1>

					<p>
						This authentication session has
						expired.

						Please return to the home page
						and try again.
					</p>`
				)
			);
		}

		isWebOAuth = true;
	}

	// -------------------------------------------------------------------------
	// Existing Discord OAuth flow.
	// -------------------------------------------------------------------------

	const parsedState = isWebOAuth
		? null
		: parseState(stateString);

	if (
		!isWebOAuth &&
		!parsedState
	) {
		return res.status(400).send(
			page(
				"Verification Failed",
				`<h1>
					Invalid Request
				</h1>

				<p>
					The verification link has expired
					or was tampered with.

					Please start again from Discord.
				</p>`
			)
		);
	}

	// -------------------------------------------------------------------------
	// Required configuration.
	// -------------------------------------------------------------------------

	if (
		!ROBLOX_OAUTH_CLIENT_ID ||
		!ROBLOX_OAUTH_CLIENT_SECRET ||
		!VERIFY_PUBLIC_URL
	) {
		console.warn(
			"[verify] missing required OAuth configuration"
		);

		return res.status(500).send(
			page(
				"Verification Failed",
				`<h1>
					Service Misconfigured
				</h1>

				<p>
					This service is missing required
					configuration.

					Please contact Conjures staff.
				</p>`
			)
		);
	}

	try {
		// -----------------------------------------------------------------------
		// Exchange authorization code for Roblox access token.
		// -----------------------------------------------------------------------

		const tokenBody =
			new URLSearchParams({
				client_id:
					ROBLOX_OAUTH_CLIENT_ID,

				client_secret:
					ROBLOX_OAUTH_CLIENT_SECRET,

				grant_type:
					"authorization_code",

				code:
					String(code),

				redirect_uri:
					redirectUri(),
			});

		const tokenResponse =
			await fetch(
				TOKEN_URL,
				{
					method: "POST",

					headers: {
						"Content-Type":
							"application/x-www-form-urlencoded",
					},

					body:
						tokenBody.toString(),
				}
			);

		if (!tokenResponse.ok) {
			const responseText =
				await tokenResponse
					.text()
					.catch(() => "");

			console.warn(
				`[verify] token exchange failed ${tokenResponse.status}: ${responseText}`
			);

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>
						Roblox Error
					</h1>

					<p>
						Couldn't complete authentication
						with Roblox.

						Please try again.
					</p>`
				)
			);
		}

		const tokenData =
			await tokenResponse.json();

		if (!tokenData.access_token) {
			console.warn(
				"[verify] Roblox response did not contain access_token"
			);

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>
						Roblox Error
					</h1>

					<p>
						Roblox did not return a valid
						authentication token.

						Please try again.
					</p>`
				)
			);
		}

		// -----------------------------------------------------------------------
		// Retrieve Roblox profile.
		// -----------------------------------------------------------------------

		const userResponse =
			await fetch(
				USERINFO_URL,
				{
					headers: {
						Authorization:
							`Bearer ${tokenData.access_token}`,
					},
				}
			);

		if (!userResponse.ok) {
			console.warn(
				`[verify] userinfo request failed ${userResponse.status}`
			);

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>
						Roblox Error
					</h1>

					<p>
						Couldn't read your Roblox profile.

						Please try again.
					</p>`
				)
			);
		}

		const userData =
			await userResponse.json();

		// Roblox OAuth "sub" is the Roblox User ID.
		const robloxUserId =
			userData.sub;

		const robloxUsername =
			userData.preferred_username;

		if (!robloxUserId) {
			console.warn(
				"[verify] Roblox userinfo response missing sub"
			);

			return res.status(502).send(
				page(
					"Verification Failed",
					`<h1>
						Roblox Error
					</h1>

					<p>
						Roblox didn't return a valid
						Roblox User ID.

						Please try again.
					</p>`
				)
			);
		}

		const displayUsername =
			robloxUsername ||
			"your Roblox account";

		// -----------------------------------------------------------------------
		// PUBLIC ENTRY LINK FLOW
		// -----------------------------------------------------------------------
		//
		// No Discord ID exists here.
		//
		// Therefore:
		//
		// - no pending_verifications insert
		// - no Discord association
		// - no role assignment
		// - no nickname update
		// - no bot request
		//
		// -----------------------------------------------------------------------

		if (isWebOAuth) {
			return res.send(
				page(
					"Roblox Authentication Successful",
					`<span class="badge">
						Authentication Successful
					</span>

					<h1>
						Roblox authentication successful
					</h1>

					<p>
						You successfully authenticated a
						Roblox account with Conjures Verify.
					</p>

					<p>
						<strong>
							Roblox Username:
						</strong>

						${escapeHtml(displayUsername)}
					</p>

					<p>
						This direct entry flow does not link
						your Roblox account to a Discord
						account and does not create a Conjures
						verification record.
					</p>

					<p>
						The authentication flow has completed
						successfully.

						You may now close this window.
					</p>`
				)
			);
		}

		// -----------------------------------------------------------------------
		// DISCORD VERIFICATION FLOW
		// -----------------------------------------------------------------------
		//
		// Existing behavior preserved.
		//
		// This is where the Discord ID and Roblox ID are placed into
		// pending_verifications for the bot to process.
		// -----------------------------------------------------------------------

		if (pool) {
			await pool.query(
				`
				insert into pending_verifications
				(
					discord_id,
					roblox_user_id,
					roblox_username
				)
				values ($1, $2, $3)
				`,
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
				`<span class="badge">
					Success
				</span>

				<h1>
					Roblox account linked
				</h1>

				<p>
					Linked as
					<strong>
						${escapeHtml(displayUsername)}
					</strong>.
				</p>

				<p>
					You can close this tab and return to Discord.
					Your role and nickname will update within
					a few seconds.
				</p>`
			)
		);

	} catch (err) {
		console.error(
			"[verify] callback failed -",
			err
		);

		return res.status(500).send(
			page(
				"Verification Failed",
				`<h1>
					Something Went Wrong
				</h1>

				<p>
					Please try again.

					If this keeps happening, contact
					Conjures staff.
				</p>`
			)
		);
	}
});

// -----------------------------------------------------------------------------
// Start server
// -----------------------------------------------------------------------------

app.listen(PORT, () => {
	console.log(
		`[verify] listening on ${PORT}`
	);
});
