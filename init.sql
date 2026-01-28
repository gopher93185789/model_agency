CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TYPE role AS ENUM ('model', 'fotograaf', 'docent');


CREATE TABLE IF NOT EXISTS app_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role role NOT NULL,
    school_email VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(50) NOT NULL,
    password_hash BYTEA
);

CREATE INDEX IF NOT EXISTS idx_app_users_school_email
    ON app_users (school_email);


-- Profile holds single profile image as name + data
CREATE TABLE IF NOT EXISTS profile (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES app_users(id) ON DELETE CASCADE,
    approved BOOLEAN DEFAULT false,
    profile_image_name TEXT,
    profile_image_data BYTEA,
    description TEXT
);

CREATE TABLE IF NOT EXISTS model_info (
    id UUID REFERENCES profile(id),
    height INT DEFAULT 0,
    bust INT DEFAULT 0,
    waist INT DEFAULT 0,
    hips INT DEFAULT 0,
    location TEXT,
    total_shots INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS portfolio_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID REFERENCES profile(id) ON DELETE CASCADE,
    image_name TEXT,
    image_data BYTEA,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_portfolio_profile ON portfolio_images(profile_id);
