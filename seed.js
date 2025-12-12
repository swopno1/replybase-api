


// seed.js
require('dotenv').config(); // Make sure you have your .env file locally!
const { Pool } = require('pg');
const { encrypt } = require('./utils/crypto');

// Use your PUBLIC Coolify DB URL here for local seeding
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function run() {
  console.log("Connecting to DB...");

  // --- PASTE YOUR DATA HERE ---
  const MY_PAGE_ID = "103913155330354"; // e.g. "1234567890"
  const MY_GENERATED_TOKEN = "EAAaUpDEONv4BQAwbct1sNxU3ilZBPRJG1SUCjrk9ESIkz0XROdJZBlxiLFZAQZA4x1DPXLQLRx18sfklzX2bnnCHgX1tC2ZCYZCURnzr0TbQ2KDs5HcxnIVfclSdmEZBPXDNQig8VVZBkMGZATdoqUgCyLoFcK3tjWTzi4hPFnQKaGheS9wAqeVlGXzRBVPGZAW4jmsLyleiZBPZChTYrsh6L5JjxAZDZD"; // Paste the long token here
  const MY_EMAIL = "amirhossain.limon@gmail.com";
  // ----------------------------

  // 1. Encrypt the token
  const { iv, encryptedData } = encrypt(MY_GENERATED_TOKEN);

  try {
    // 2. Create the Tenant (Client)
    // We use ON CONFLICT DO NOTHING to avoid errors if you run this twice
    const tenantRes = await pool.query(`
            INSERT INTO tenants (email, password_hash) 
            VALUES ($1, 'dummy_hash') 
            ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
            RETURNING id
        `, [MY_EMAIL]);

    // If the tenant already existed, we need to fetch the ID
    let tenantId;
    if (tenantRes.rows.length > 0) {
      tenantId = tenantRes.rows[0].id;
    } else {
      const fetchRes = await pool.query(`SELECT id FROM tenants WHERE email = $1`, [MY_EMAIL]);
      tenantId = fetchRes.rows[0].id;
    }

    console.log(`Tenant ID: ${tenantId}`);

    // 3. Insert the Credentials
    // This links the Page ID to the Encrypted Token
    await pool.query(`
            INSERT INTO credentials (tenant_id, platform, page_id, encrypted_token, encryption_iv)
            VALUES ($1, 'facebook', $2, $3, $4)
            ON CONFLICT (tenant_id, platform) 
            DO UPDATE SET 
                encrypted_token = $3, 
                encryption_iv = $4,
                page_id = $2
        `, [tenantId, MY_PAGE_ID, encryptedData, iv]);

    console.log("✅ SUCCESS: Token encrypted and saved to Database!");

  } catch (e) {
    console.error("Error:", e);
  } finally {
    pool.end();
  }
}

run();