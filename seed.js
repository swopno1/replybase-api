require("dotenv").config();
const { Pool } = require("pg");
const { encrypt } = require("./utils/crypto");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function run() {
  // REPLACE THESE WITH REAL VALUES FROM YOUR FB DEVELOPER ACCOUNT
  const PAGE_ID = "123456789";
  const FB_ACCESS_TOKEN = "EAAG...";

  const { iv, encryptedData } = encrypt(FB_ACCESS_TOKEN);

  // 1. Create Tenant
  const tenantRes = await pool.query(
    `INSERT INTO tenants (email, password_hash) VALUES ('test@user.com', 'hash') RETURNING id`
  );
  const tenantId = tenantRes.rows[0].id;

  // 2. Create Credentials
  await pool.query(
    `
        INSERT INTO credentials (tenant_id, platform, page_id, encrypted_token, encryption_iv)
        VALUES ($1, 'facebook', $2, $3, $4)
    `,
    [tenantId, PAGE_ID, encryptedData, iv]
  );

  console.log("Database seeded!");
  pool.end();
}
run();
