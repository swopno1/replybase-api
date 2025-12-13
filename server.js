require('dotenv').config();
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
// 2. UNIFIED FACEBOOK LOGIN & CONNECT
// ==========================================

// A. Initiate Login (Front-end links here)
app.get('/auth/facebook/login', (req, res) => {
  // We ask for email AND page permissions immediately
  const scopes = 'email,public_profile,pages_messaging,pages_show_list,pages_manage_metadata,pages_read_engagement';
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/facebook/callback_login`;

  const url = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${process.env.FB_APP_ID}&redirect_uri=${redirectUri}&scope=${scopes}`;
  res.json({ url });
});

// B. Handle Login Callback
app.get('/auth/facebook/callback_login', async (req, res) => {
  const { code } = req.query;
  const redirectUri = `${process.env.API_BASE_URL || 'https://api.investorhints.com'}/auth/facebook/callback_login`;

  if (!code) return res.status(400).send("No code received from Facebook");

  try {
    // 1. Exchange Code for Token
    const tokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
      params: {
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri: redirectUri,
        code: code
      }
    });
    const userAccessToken = tokenRes.data.access_token;

    // 2. Get User Profile (Email & ID)
    const profileRes = await axios.get(`https://graph.facebook.com/v18.0/me?fields=id,name,email`, {
      params: { access_token: userAccessToken }
    });
    const { id: fbUserId, name, email } = profileRes.data;

    // 3. Find or Create Tenant
    // Note: In a real app, handle cases where email exists but was signed up via password (merge accounts).
    let tenant;
    const userCheck = await pool.query(`SELECT * FROM tenants WHERE email = $1`, [email]);

    if (userCheck.rows.length > 0) {
      tenant = userCheck.rows[0];
      console.log(`Existing user logged in: ${email}`);
    } else {
      // Create new tenant
      const newTenant = await pool.query(
        `INSERT INTO tenants (email, password_hash, company_name) VALUES ($1, 'fb_oauth', $2) RETURNING *`,
        [email, name]
      );
      tenant = newTenant.rows[0];
      console.log(`New user created: ${email}`);
    }

    // 4. AUTOMATICALLY Save Page Tokens (Since we have the permission!)
    // Exchange for Long-Lived Token first
    const longTokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
      params: {
        grant_type: 'fb_exchange_token',
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        fb_exchange_token: userAccessToken
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
            `, [tenant.id, page.id, encryptedData, iv]);

      // Subscribe Webhook
      try {
        await axios.post(`https://graph.facebook.com/${page.id}/subscribed_apps`, {}, {
          params: { access_token: page.access_token, subscribed_fields: 'messages' }
        });
      } catch (e) { console.error("Webhook sub failed", e.message); }
    }

    // 5. Generate JWT Session
    const token = jwt.sign({ id: tenant.id }, process.env.JWT_SECRET);

    // 6. Redirect to Frontend with Token
    // We pass the token in the URL params so the frontend can grab it.
    res.redirect(`https://site.investorhints.com/auth-callback?token=${token}&tenant_id=${tenant.id}`);

  } catch (err) {
    console.error("Login Error:", err.message);
    res.redirect(`https://site.investorhints.com?error=login_failed`);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wrapper API running on port ${PORT}`));

