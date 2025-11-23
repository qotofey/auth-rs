CREATE EXTENSION "uuid-ossp";

CREATE TYPE genders AS ENUM ('female', 'male');

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuidv7(),
  first_name VARCHAR(255),
  middle_name VARCHAR(255),
  last_name VARCHAR(255),
  birthdate DATE,
  gender genders,
  blocked_at TIMESTAMP,
  deleted_at TIMESTAMP
);

