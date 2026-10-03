-- Banco D1: checklist_ppci (já criado e com estas tabelas)
CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, usuario TEXT NOT NULL UNIQUE COLLATE NOCASE, nome TEXT NOT NULL, senha_hash TEXT NOT NULL, salt TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0, ativo INTEGER NOT NULL DEFAULT 1, criado INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessoes (token TEXT PRIMARY KEY, usuario_id INTEGER NOT NULL, expira INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sessoes_usuario ON sessoes(usuario_id);
CREATE TABLE IF NOT EXISTS checklists (id TEXT PRIMARY KEY, dados TEXT NOT NULL, cliente TEXT, cidade TEXT, status TEXT, criado_por INTEGER, criado INTEGER NOT NULL, atualizado INTEGER NOT NULL, atualizado_por INTEGER);
CREATE INDEX IF NOT EXISTS idx_checklists_atualizado ON checklists(atualizado DESC);
CREATE TABLE IF NOT EXISTS fotos (id TEXT PRIMARY KEY, checklist_id TEXT NOT NULL, item_id TEXT, mime TEXT NOT NULL, dados BLOB NOT NULL, tamanho INTEGER, criado INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_fotos_checklist ON fotos(checklist_id);
CREATE TABLE IF NOT EXISTS responsaveis (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL UNIQUE COLLATE NOCASE, criado INTEGER NOT NULL);
