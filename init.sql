CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE role AS ENUM ('model', 'fotograaf', 'docent');

CREATE TABLE IF NOT EXISTS app_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role role NOT NULL,
    school_id VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    password_hash BYTEA
);

CREATE INDEX IF NOT EXISTS ON app_users(school_id);

CREATE TABLE IF NOT EXISTS profile (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES app_users(id) ON DELETE CASCADE,
    approved BOOLEAN DEFAULT false,
    profile_image_url TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS profile_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID REFERENCES profile(id) ON DELETE CASCADE,
    image_url TEXT NOT NULL
);
