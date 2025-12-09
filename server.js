require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const { Pool } = require("pg");
const axios = require("axios");
const { decrypt, encrypt } = require("./utils/crypto");

const app = express();
app.use(bodyParser.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// 1. Meta Verification Endpoint (Required when you first connect the webhook)
app.get("/webhooks/meta", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode && token === process.env.META_VERIFY_TOKEN) {
    res.status(200).send(challenge);
  } else {
    res.sendStatus(403);
  }
});

// 2. The Main Event Handler
app.post("/webhooks/meta", async (req, res) => {
  const body = req.body;

  if (body.object === "page") {
    // Iterate over entries (Meta sends batched events)
    for (const entry of body.entry) {
      const webhookEvent = entry.messaging[0];
      const senderPsid = webhookEvent.sender.id;
      const pageId = entry.id; // This identifies WHICH tenant

      // A. Find the Tenant based on Page ID
      const result = await pool.query(
        "SELECT * FROM credentials WHERE page_id = $1 AND platform = $2",
        [pageId, "facebook"]
      );

      if (result.rows.length > 0) {
        const creds = result.rows[0];

        // B. Decrypt the Token
        const accessToken = decrypt({
          iv: creds.encryption_iv,
          encryptedData: creds.encrypted_token,
        });

        // C. Forward to n8n (Headless)
        // We pass the message AND the decrypted token
        try {
          await axios.post(process.env.N8N_WEBHOOK_URL, {
            message: webhookEvent.message.text,
            sender_id: senderPsid,
            page_id: pageId,
            tenant_id: creds.tenant_id,
            credentials: {
              access_token: accessToken, // Dynamic Credential for n8n
            },
          });
          console.log(`Forwarded message for Tenant ${creds.tenant_id}`);
        } catch (err) {
          console.error("n8n Error:", err.message);
        }
      }
    }
    res.status(200).send("EVENT_RECEIVED");
  } else {
    res.sendStatus(404);
  }
});

app.listen(3000, () => console.log("API running on port 3000"));
