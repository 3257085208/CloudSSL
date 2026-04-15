CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL UNIQUE,
  sans_json TEXT DEFAULT '[]',
  acme_directory TEXT NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory',
  acme_account_name TEXT DEFAULT 'default',
  account_key_algorithm TEXT DEFAULT 'ecdsa-p256',
  cert_key_algorithm TEXT DEFAULT 'ecdsa-p256',
  auto_renew INTEGER NOT NULL DEFAULT 1,
  disable_cname INTEGER NOT NULL DEFAULT 0,
  skip_dns_precheck INTEGER NOT NULL DEFAULT 0,
  dns_server_1 TEXT DEFAULT '',
  dns_server_2 TEXT DEFAULT '',
  validation_mode TEXT NOT NULL DEFAULT 'manual',
  dns_provider TEXT DEFAULT '',
  dns_api_token_encrypted TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'draft',
  last_error TEXT DEFAULT '',
  expires_at TEXT DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  cert_path TEXT NOT NULL,
  chain_path TEXT NOT NULL,
  fullchain_path TEXT NOT NULL,
  privkey_path TEXT NOT NULL,
  pubkey_path TEXT NOT NULL,
  serial_number TEXT DEFAULT '',
  not_before TEXT DEFAULT NULL,
  not_after TEXT DEFAULT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(domain_id) REFERENCES domains(id)
);

CREATE TABLE IF NOT EXISTS acme_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  directory_url TEXT NOT NULL,
  email TEXT DEFAULT '',
  key_algorithm TEXT NOT NULL DEFAULT 'ecdsa-p256',
  key_path TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS renew_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  success INTEGER NOT NULL DEFAULT 0,
  message TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(domain_id) REFERENCES domains(id)
);
