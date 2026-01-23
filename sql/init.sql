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


CREATE TABLE IF NOT EXISTS profile (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES app_users(id) ON DELETE CASCADE,
    approved BOOLEAN DEFAULT false,
    profile_image []BYTEA,
    description TEXT
);


CREATE TABLE IF NOT EXISTS model_info (
    id UUID REFERENCES profile(id),
    height INT DEFAULT 0,
    bust INT DEFAULT 0,
    waist INT DEFAULT 0,
    hips INT DEFAULT 0
    location TEXT
    total_shots INT DEFAULT 0,
);

CREATE TABLE IF NOT EXISTS profile_image (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID REFERENCES profile(id) ON DELETE CASCADE,
    image_data []BYTEA NOT NULL
);
