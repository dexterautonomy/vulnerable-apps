-- Seed data for the vulnerable test target. Secrets are fake/for-testing only.

INSERT INTO users (id, username, password, email, role, ssn, credit_card, api_key, reset_token, is_admin, balance) VALUES
 (1, 'admin',   'admin123',        'admin@vuln.local',   'ADMIN', '111-22-3333', '4111111111111111', 'API-ADMIN-0001', 'reset-admin-tok', TRUE,  100000.00),
 (2, 'alice',   'password1',       'alice@vuln.local',   'USER',  '222-33-4444', '4222222222222222', 'API-ALICE-0002', 'reset-alice-tok', FALSE, 1500.00),
 (3, 'bob',     'qwerty',          'bob@vuln.local',     'USER',  '333-44-5555', '4333333333333333', 'API-BOB-0003',   'reset-bob-tok',   FALSE, 250.00),
 (4, 'carol',   'letmein',         'carol@vuln.local',   'USER',  '444-55-6666', '4444333322221111', 'API-CAROL-0004', 'reset-carol-tok', FALSE, 9999.00),
 (5, 'service', 'svc-p@ss-2020',   'service@vuln.local', 'SERVICE','555-66-7777','4444555566667777', 'API-SVC-0005',   'reset-svc-tok',   FALSE, 0.00);

INSERT INTO accounts (id, user_id, account_number, balance, type) VALUES
 (1, 1, 'ACC-0001-ADMIN', 100000.00, 'CHECKING'),
 (2, 2, 'ACC-0002-ALICE', 1500.00,  'CHECKING'),
 (3, 3, 'ACC-0003-BOB',   250.00,   'SAVINGS'),
 (4, 4, 'ACC-0004-CAROL', 9999.00,  'CHECKING');

INSERT INTO products (id, name, description, price, owner_id, stock) VALUES
 (1, 'Widget',   'A standard widget',   9.99,  2, 100),
 (2, 'Gadget',   'A premium gadget',    19.99, 2, 50),
 (3, 'Gizmo',    'A shiny gizmo',       4.99,  3, 200),
 (4, 'Doohickey','Limited edition',     99.99, 4, 5);

INSERT INTO orders (id, user_id, product_id, quantity, total, status) VALUES
 (1, 2, 1, 3, 29.97, 'PAID'),
 (2, 3, 3, 10, 49.90, 'PENDING'),
 (3, 4, 4, 1, 99.99, 'SHIPPED');

INSERT INTO documents (id, owner_id, filename, filepath, content, is_public) VALUES
 (1, 1, 'admin-notes.txt', '/data/admin-notes.txt', 'Internal only: master key MASTER-API-KEY-DO-NOT-SHARE-0001', FALSE),
 (2, 2, 'alice-resume.txt', '/data/alice-resume.txt', 'Alice resume contents', FALSE),
 (3, 3, 'public-flyer.txt', '/data/public-flyer.txt', 'Public flyer', TRUE);

INSERT INTO comments (id, author, body) VALUES
 (1, 'alice', 'First!'),
 (2, 'bob',   'Nice product');

INSERT INTO messages (id, sender_id, recipient_id, subject, body) VALUES
 (1, 2, 3, 'Hi Bob', 'Private message from Alice to Bob'),
 (2, 1, 2, 'Welcome', 'Admin welcomes Alice');

INSERT INTO api_clients (id, client_id, client_secret, scopes, owner_id) VALUES
 (1, 'client-admin', 'secret-admin-xyz', 'read,write,admin', 1),
 (2, 'client-alice', 'secret-alice-abc', 'read', 2);

INSERT INTO audit_logs (id, action, username, ip, detail) VALUES
 (1, 'LOGIN', 'admin', '127.0.0.1', 'admin logged in');

-- Seeded rows above use explicit ids, so advance each IDENTITY sequence past them
-- (otherwise app-side INSERTs collide on id=1). Valid on both PostgreSQL and H2.
ALTER TABLE users       ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE accounts    ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE products    ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE orders      ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE documents   ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE comments    ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE messages    ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE api_clients ALTER COLUMN id RESTART WITH 1000;
ALTER TABLE audit_logs  ALTER COLUMN id RESTART WITH 1000;
