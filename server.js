require('dotenv').config();

// Crash logging
process.on('uncaughtException', err => {
  console.error('There was an uncaught error', err)
  process.exit(1) //mandatory (as per the Node.js docs)
})

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason)
  // Recommended: send the information to sentry.io or similar
})

const express = require('express');
const { Pool } = require('pg');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { decrypt, encrypt } = require('./utils/crypto');

const app = express();
app.use(express.json());
// Enable CORS so your Frontend (site.investorhints.com) can call this
const cors = require('cors');
app.use(cors());

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false // Keep false for Coolify internal network
});


// ==========================================
// 1. USER AUTH (Register/Login)
// ==========================================

app.post('/auth/register', async (req, res) => {
  const { email, password, company_name } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO tenants (email, password_hash, company_name) VALUES ($1, $2, $3) RETURNING id, email`,
      [email, hash, company_name]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: "Email likely exists" });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query(`SELECT * FROM tenants WHERE email = $1`, [email]);

  if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);

  if (!valid) return res.status(400).json({ error: "Invalid password" });

  // Create Session Token
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  res.json({ token, user: { id: user.id, email: user.email } });
});


// ==========================================
// 2. SOCIAL AUTH (Facebook & Google)
// ==========================================

// ------------------------------------------
// FACEBOOK LOGIN (New User / Sign In)
// ------------------------------------------

app.get('/auth/facebook/login', (req, res) => {
  // We ask for email AND page permissions immediately (for a seamless "sign up with FB")
  const scopes = 'email,public_profile,pages_messaging,pages_show_list,pages_manage_metadata,pages_read_engagement';
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/facebook/callback_login`;

  const url = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${process.env.FB_APP_ID}&redirect_uri=${redirectUri}&scope=${scopes}`;
  res.json({ url });
});

app.get('/auth/facebook/callback_login', async (req, res) => {
  const { code } = req.query;
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/facebook/callback_login`;

  if (!code) return res.status(400).send("No code received");

  try {
    // 1. Exchange Code
    const tokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
      params: {
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri: redirectUri,
        code: code
      }
    });
    const userAccessToken = tokenRes.data.access_token;

    // 2. Get Profile
    const profileRes = await axios.get(`https://graph.facebook.com/v18.0/me?fields=id,name,email`, {
      params: { access_token: userAccessToken }
    });
    const { id: fbUserId, name, email } = profileRes.data;

    // CHECK: If email is missing, we cannot create an account (User might have signed up with Phone # or declined permission)
    if (!email) {
      console.warn(`Login failed: No email for FB User ${name} (${fbUserId})`);
      return res.redirect(`https://site.investorhints.com/login?error=missing_email`);
    }

    // 3. Find or Create Tenant
    let tenant;
    const userCheck = await pool.query(`SELECT * FROM tenants WHERE email = $1`, [email]);

    if (userCheck.rows.length > 0) {
      tenant = userCheck.rows[0];
    } else {
      const newTenant = await pool.query(
        `INSERT INTO tenants (email, password_hash, company_name) VALUES ($1, 'fb_oauth', $2) RETURNING *`,
        [email, name]
      );
      tenant = newTenant.rows[0];
    }

    // 4. Update/Link Pages (Auto-magically)
    await linkFacebookPages(tenant.id, userAccessToken);

    // 5. Session
    const token = jwt.sign({ id: tenant.id }, process.env.JWT_SECRET);
    res.redirect(`https://site.investorhints.com/auth-callback?token=${token}&tenant_id=${tenant.id}`);

  } catch (err) {
    console.error("FB Login Error:", err.message);
    res.redirect(`https://site.investorhints.com?error=login_failed`);
  }
});


// ------------------------------------------
// FACEBOOK CONNECT (Link Pages to Existing User)
// ------------------------------------------

// Protected: User must be logged in to ask for the Connect URL
app.get('/auth/facebook/connect', authenticate, (req, res) => {
  const scopes = 'pages_messaging,pages_show_list,pages_manage_metadata,pages_read_engagement'; // No email needed if just connecting pages
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/facebook/callback_connect`;

  // We pass tenant_id in 'state' so we know who to link to in the callback
  // In production, sign this state to prevent tampering!
  const state = req.user.id;

  const url = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${process.env.FB_APP_ID}&redirect_uri=${redirectUri}&scope=${scopes}&state=${state}`;
  res.json({ url });
});

app.get('/auth/facebook/callback_connect', async (req, res) => {
  const { code, state } = req.query; // state is the tenant_id
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/facebook/callback_connect`;

  if (!code || !state) return res.redirect(`https://site.investorhints.com/dashboard?error=connect_failed`);

  try {
    // 1. Exchange Code
    const tokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
      params: {
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri: redirectUri,
        code: code
      }
    });
    const userAccessToken = tokenRes.data.access_token;

    // 2. Link Pages
    await linkFacebookPages(state, userAccessToken);

    // 3. Back to Dashboard
    res.redirect(`https://site.investorhints.com/dashboard?success=facebook_connected`);

  } catch (err) {
    console.error("FB Connect Error:", err.message);
    res.redirect(`https://site.investorhints.com/dashboard?error=connect_failed`);
  }
});

// Middleware to check JWT (Protect routes)
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Helper: Shared Logic to Link Pages
async function linkFacebookPages(tenantId, shortLivedToken) {
  // Exchange for Long-Lived
  const longTokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
    params: {
      grant_type: 'fb_exchange_token',
      client_id: process.env.FB_APP_ID,
      client_secret: process.env.FB_APP_SECRET,
      fb_exchange_token: shortLivedToken
    }
  });
  const longToken = longTokenRes.data.access_token;

  // Fetch Accounts
  const pagesRes = await axios.get(`https://graph.facebook.com/v18.0/me/accounts`, {
    params: { access_token: longToken }
  });

  // Save Pages
  for (const page of pagesRes.data.data) {
    const { iv, encryptedData } = encrypt(page.access_token);
    await pool.query(`
              INSERT INTO credentials (tenant_id, platform, page_id, encrypted_token, encryption_iv)
              VALUES ($1, 'facebook', $2, $3, $4)
              ON CONFLICT (tenant_id, platform) 
              DO UPDATE SET encrypted_token = $3, encryption_iv = $4
          `, [tenantId, page.id, encryptedData, iv]);

    try {
      await axios.post(`https://graph.facebook.com/${page.id}/subscribed_apps`, {}, {
        params: { access_token: page.access_token, subscribed_fields: 'messages' }
      });
    } catch (e) { console.error("Webhook sub failed", e.message); }
  }
}


// ------------------------------------------
// GOOGLE LOGIN (New)
// ------------------------------------------

app.get('/auth/google', (req, res) => {
  const scopes = 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email';
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/google/callback`;

  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=${scopes}&access_type=offline`;
  res.json({ url });
});

app.get('/auth/google/callback', async (req, res) => {
  const { code } = req.query;
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/google/callback`;

  if (!code) return res.status(400).send("No code from Google");

  try {
    // 1. Exchange Code for Token
    const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    const { access_token } = tokenRes.data;

    // 2. Get Profile
    const profileRes = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const { email, name } = profileRes.data;

    // 3. Upsert User
    let tenant;
    const userCheck = await pool.query(`SELECT * FROM tenants WHERE email = $1`, [email]);

    if (userCheck.rows.length > 0) {
      tenant = userCheck.rows[0];
    } else {
      const newTenant = await pool.query(
        `INSERT INTO tenants (email, password_hash, company_name) VALUES ($1, 'google_oauth', $2) RETURNING *`,
        [email, name]
      );
      tenant = newTenant.rows[0];
    }

    // 4. Session
    const token = jwt.sign({ id: tenant.id }, process.env.JWT_SECRET);
    res.redirect(`https://site.investorhints.com/auth-callback?token=${token}&tenant_id=${tenant.id}`);

  } catch (err) {
    console.error("Google Login Error:", err.message);
    res.redirect(`https://site.investorhints.com?error=google_login_failed`);
  }
});


// ==========================================
// 3. WEBHOOK HANDLER (Existing Code)
// ==========================================

// --- ADD THIS DEBUG MIDDLEWARE HERE, we'll remove this later ---
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  if (req.method === 'POST') {
    // Log the raw body so we see EXACTLY what Meta is sending
    console.log('Incoming Payload:', JSON.stringify(req.body, null, 2));
  }
  next();
});


// --- ROUTE 1: Meta Verification (The Handshake) ---
app.get("/webhooks/meta", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  // Check if the token matches what you set in .env
  if (mode && token === process.env.META_VERIFY_TOKEN) {
    console.log("WEBHOOK_VERIFIED");
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// --- ROUTE 2: Handle Incoming Messages ---
app.post("/webhooks/meta", async (req, res) => {
  const body = req.body;

  // 1. Check if this is a Page event
  if (body.object === "page") {
    // 2. Iterate over batched entries
    for (const entry of body.entry) {
      // Get the message details
      const webhookEvent = entry.messaging ? entry.messaging[0] : null;

      if (webhookEvent && webhookEvent.message) {
        const pageId = entry.id; // This is the ID of the Client's Facebook Page
        const senderId = webhookEvent.sender.id;
        const messageText = webhookEvent.message.text;

        console.log(`Received message for Page ID: ${pageId}`);

        try {
          // 3. Lookup Tenant in DB based on Page ID
          const query = `
                        SELECT tenant_id, encrypted_token, encryption_iv 
                        FROM credentials 
                        WHERE page_id = $1 AND platform = 'facebook'
                    `;
          const result = await pool.query(query, [pageId]);

          if (result.rows.length > 0) {
            const creds = result.rows[0];

            // 4. Decrypt the Access Token
            const accessToken = decrypt({
              iv: creds.encryption_iv,
              encryptedData: creds.encrypted_token,
            });

            // 5. Forward to n8n (Headless)
            // We send the message + the DECRYPTED token to n8n
            await axios.post(process.env.N8N_WEBHOOK_URL, {
              tenant_id: creds.tenant_id,
              page_id: pageId,
              sender_id: senderId,
              message: messageText,
              credentials: {
                access_token: accessToken,
              },
            });

            console.log(`-> Forwarded to n8n for Tenant: ${creds.tenant_id}`);
          } else {
            console.warn(`No tenant found for Page ID: ${pageId}`);
          }
        } catch (error) {
          console.error("Error processing webhook:", error.message);
        }
      }
    }
    // Return 200 OK immediately to Meta (otherwise they stop sending)
    res.status(200).send("EVENT_RECEIVED");
  } else {
    res.sendStatus(404);
  }
});


// ==========================================
// 4. PRIVATE DASHBOARD API (New)
// ==========================================

// GET /tenant/status - Returns connected platforms
app.get('/tenant/status', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT platform, page_id, created_at FROM credentials WHERE tenant_id = $1`,
      [req.user.id]
    );
    res.json({ connections: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Db error" });
  }
});

// POST /tenant/whatsapp - Manual WhatsApp Connection
app.post('/tenant/whatsapp', authenticate, async (req, res) => {
  const { phone_id, access_token } = req.body;
  // For WhatsApp, we often paste the Permanent Token manually in MVP
  const { iv, encryptedData } = encrypt(access_token);

  try {
    await pool.query(`
            INSERT INTO credentials (tenant_id, platform, page_id, encrypted_token, encryption_iv)
            VALUES ($1, 'whatsapp', $2, $3, $4)
            ON CONFLICT (tenant_id, platform) 
            DO UPDATE SET encrypted_token = $3, encryption_iv = $4
        `, [req.user.id, phone_id, encryptedData, iv]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to save WhatsApp creds" });
  }
});


// ==========================================
// 5. FACEBOOK COMPLIANCE & DATA DELETION
// ==========================================

// Helper to decode FB Signed Request (Optional but recommended for verifying payload)
const parseSignedRequest = (signedRequest, appSecret) => {
  try {
    const [encodedSig, payload] = signedRequest.split('.');
    const data = JSON.parse(Buffer.from(payload, 'base64').toString());
    return data;
  } catch (e) {
    return null;
  }
};

// Callback: Deauthorize (User removes App from FB Settings)
app.post('/auth/facebook/deauthorize', async (req, res) => {
  const signedRequest = req.body.signed_request;
  const data = parseSignedRequest(signedRequest, process.env.FB_APP_SECRET);

  if (data && data.user_id) {
    const fbUserId = data.user_id;
    console.log(`[Deauth] User ${fbUserId} removed the app.`);

    // MVP Action: Mark credentials as inactive in DB (Don't delete yet for logs)
    // You would need to map fbUserId to your tenant_id via an API call or DB lookup
    // For now, we just log it to satisfy the requirement.
  }

  // Facebook expects a success response
  res.json({ success: true });
});

// Callback: Data Deletion Request (User requests data deletion)
app.post('/auth/facebook/delete-data', async (req, res) => {
  const signedRequest = req.body.signed_request;
  const data = parseSignedRequest(signedRequest, process.env.FB_APP_SECRET);

  if (data && data.user_id) {
    const fbUserId = data.user_id;
    const confirmationCode = `del_${Date.now()}`; // Generate a tracking code

    console.log(`[Delete Data] Request from ${fbUserId}. Code: ${confirmationCode}`);

    // MVP Action: Perform deletion logic here (e.g., DELETE FROM tenants WHERE...)

    // Facebook Requirement: Return a URL where they can check status
    // We point this to a generic status page on your frontend
    const statusUrl = `https://site.investorhints.com/deletion-status?id=${confirmationCode}`;

    return res.json({
      url: statusUrl,
      confirmation_code: confirmationCode,
    });
  }

  res.sendStatus(400);
});


// ==========================================
// 6. HEALTH & STATUS
// ==========================================

app.get('/health', async (req, res) => {
  try {
    // Check DB connection
    await pool.query('SELECT NOW()');
    res.status(200).json({ status: 'ok', database: 'connected' });
  } catch (err) {
    console.error('Health check failed:', err);
    res.status(500).json({ status: 'error', database: 'disconnected' });
  }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wrapper API running on port ${PORT}`));
