require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const axios = require("axios");
const { decrypt } = require("./utils/crypto");

const app = express();
app.use(express.json());

// --- ADD THIS DEBUG MIDDLEWARE HERE ---
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  if (req.method === 'POST') {
    // Log the raw body so we see EXACTLY what Meta is sending
    console.log('Incoming Payload:', JSON.stringify(req.body, null, 2));
  }
  next();
});

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Fix: Coolify internal Postgres usually does not support SSL. 
  // Since this is a private internal network, we disable SSL.
  ssl: false
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Wrapper API running on port ${PORT}`));
