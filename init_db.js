require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const sql = `
    -- 1. Enable UUID extension (Required for random IDs)
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    -- 2. Create Tenants Table
    CREATE TABLE IF NOT EXISTS tenants (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        company_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- 3. Create Credentials Table
    CREATE TABLE IF NOT EXISTS credentials (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        platform VARCHAR(50) NOT NULL,
        page_id VARCHAR(255),
        encrypted_token TEXT NOT NULL,
        encryption_iv TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(tenant_id, platform)
    );

    -- 4. Create Webhook Logs (Optional debugging)
    CREATE TABLE IF NOT EXISTS webhook_logs (
        id SERIAL PRIMARY KEY,
        tenant_id UUID,
        payload JSONB,
        status VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
`;

async function init() {
    try {
        console.log("Creating tables...");
        await pool.query(sql);
        console.log("✅ Tables created successfully!");
    } catch (err) {
        console.error("❌ Error creating tables:", err);
    } finally {
        pool.end();
    }
}

init();