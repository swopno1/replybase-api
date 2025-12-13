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
// 2. FACEBOOK OAUTH (Fixed for Browser Redirect)
// ==========================================

// Step A: Generate the Login URL (Now includes 'state' for tenant_id)
// Call this from Frontend: GET /auth/facebook/url?tenant_id=UUID
app.get('/auth/facebook/url', (req, res) => {
  const tenantId = req.query.tenant_id;

  if (!tenantId) {
    return res.status(400).json({ error: "Missing tenant_id" });
  }

  // We pass tenantId in the 'state' parameter. 
  // Facebook returns this to us exactly as is.
  const state = JSON.stringify({ tenant_id: tenantId });

  const url = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${process.env.FB_APP_ID}&redirect_uri=${process.env.FB_REDIRECT_URI}&state=${state}&scope=pages_messaging,pages_show_list,pages_manage_metadata,pages_read_engagement`;

  res.json({ url });
});

// Step B: Handle the Callback (Changed from POST to GET)
app.get('/auth/facebook/callback', async (req, res) => {
  // 1. Extract Data from Query Params (Browser Redirect)
  const { code, state } = req.query;

  if (!code || !state) {
    return res.status(400).send("Login failed: Missing code or state from Facebook.");
  }

  try {
    // 2. Decode the 'state' to get the Tenant ID
    const stateData = JSON.parse(state);
    const tenant_id = stateData.tenant_id;

    console.log(`Processing Facebook Connect for Tenant: ${tenant_id}`);

    // 3. Exchange Code for Short-Lived User Token
    const tokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
      params: {
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        redirect_uri: process.env.FB_REDIRECT_URI,
        code: code
      }
    });
    const shortToken = tokenRes.data.access_token;

    // 4. Exchange Short Token for Long-Lived User Token (60 days)
    const longTokenRes = await axios.get(`https://graph.facebook.com/v18.0/oauth/access_token`, {
      params: {
        grant_type: 'fb_exchange_token',
        client_id: process.env.FB_APP_ID,
        client_secret: process.env.FB_APP_SECRET,
        fb_exchange_token: shortToken
      }
    });
    const longToken = longTokenRes.data.access_token;

    // 5. Get User's Pages
    const pagesRes = await axios.get(`https://graph.facebook.com/v18.0/me/accounts`, {
      params: { access_token: longToken }
    });

    const pages = pagesRes.data.data;

    // 6. Save Tokens to DB
    for (const page of pages) {
      const { iv, encryptedData } = encrypt(page.access_token);

      await pool.query(`
                INSERT INTO credentials (tenant_id, platform, page_id, encrypted_token, encryption_iv)
                VALUES ($1, 'facebook', $2, $3, $4)
                ON CONFLICT (tenant_id, platform) 
                DO UPDATE SET encrypted_token = $3, encryption_iv = $4
            `, [tenant_id, page.id, encryptedData, iv]);

      // Subscribe App to Webhooks
      try {
        await axios.post(`https://graph.facebook.com/${page.id}/subscribed_apps`, {}, {
          params: {
            access_token: page.access_token,
            subscribed_fields: 'messages'
          }
        });
      } catch (subErr) {
        console.error(`Failed to subscribe page ${page.id}:`, subErr.message);
      }
    }

    // 7. FINAL SUCCESS REDIRECT
    // Redirect the user back to your Frontend Dashboard
    res.redirect('https://site.investorhints.com/dashboard?fb_status=success');

  } catch (err) {
    console.error("OAuth Error:", err.response?.data || err.message);
    // Redirect to Frontend with error
    res.redirect('https://site.investorhints.com/dashboard?fb_status=error');
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

