// Check-List de Cadastro PPCI — API (Cloudflare Worker + D1)
// Rotas em /api/*; o resto é servido de ./public (index.html).

const SESSAO_DIAS = 30;
const PBKDF2_ITER = 100000;
const FOTO_MAX = 1_900_000; // limite de linha do D1 é 2 MB

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    try {
      return await rotear(req, env, url);
    } catch (e) {
      if (e instanceof Resposta) return e.res;
      console.error(e);
      return json({ erro: "Erro interno no servidor." }, 500);
    }
  },
};

class Resposta { constructor(res) { this.res = res; } }
const json = (obj, status = 200, headers = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const falha = (msg, status = 400) => { throw new Resposta(json({ erro: msg }, status)); };
const agora = () => Date.now();

async function corpo(req) {
  try { return await req.json(); } catch { falha("Dados inválidos."); }
}

/* ---------- senha ---------- */
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
function aleatorio(n = 16) { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a); }
async function hashSenha(senha, salt) {
  const chave = await crypto.subtle.importKey("raw", new TextEncoder().encode(senha), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: PBKDF2_ITER }, chave, 256);
  return hex(bits);
}
function iguais(a, b) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function validarSenha(s) { if (typeof s !== "string" || s.length < 6) falha("A senha precisa ter pelo menos 6 caracteres."); }
const limparUsuario = (u) => String(u || "").trim().toUpperCase(); // usuário sempre em caixa alta
function validarUsuario(u) {
  if (typeof u !== "string" || !/^[a-zA-Z0-9._-]{3,30}$/.test(u)) falha("Usuário deve ter de 3 a 30 letras, números, ponto, hífen ou sublinhado, sem espaços.");
}

/* ---------- sessão ---------- */
function lerCookie(req, nome) {
  const c = req.headers.get("cookie") || "";
  for (const p of c.split(/;\s*/)) { const i = p.indexOf("="); if (i > 0 && p.slice(0, i) === nome) return decodeURIComponent(p.slice(i + 1)); }
  return null;
}
const cookieSessao = (token, maxAge) => `sessao=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

async function usuarioAtual(req, env) {
  const token = lerCookie(req, "sessao");
  if (!token) return null;
  const u = await env.DB.prepare(
    "SELECT u.id,u.usuario,u.nome,u.admin,u.ativo FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token=? AND s.expira>?"
  ).bind(token, agora()).first();
  if (!u || !u.ativo) return null;
  return { id: u.id, usuario: u.usuario, nome: u.nome, admin: !!u.admin };
}
async function exigirLogin(req, env) { const u = await usuarioAtual(req, env); if (!u) falha("Sessão expirada. Entre novamente.", 401); return u; }
async function exigirAdmin(req, env) { const u = await exigirLogin(req, env); if (!u.admin) falha("Apenas administradores podem fazer isso.", 403); return u; }

async function criarSessao(env, usuarioId) {
  const token = aleatorio(32);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessoes WHERE expira<?").bind(agora()),
    env.DB.prepare("INSERT INTO sessoes (token,usuario_id,expira) VALUES (?,?,?)").bind(token, usuarioId, agora() + SESSAO_DIAS * 864e5),
  ]);
  return token;
}
async function contarUsuarios(env) { const r = await env.DB.prepare("SELECT COUNT(*) n FROM usuarios").first(); return r.n; }

/* ---------- rotas ---------- */
async function rotear(req, env, url) {
  const m = req.method;
  const p = url.pathname.replace(/\/+$/, "");
  const seg = p.split("/").slice(2); // depois de /api

  // estado inicial: precisa criar admin? quem está logado?
  if (p === "/api/estado" && m === "GET") {
    const n = await contarUsuarios(env);
    return json({ precisaSetup: n === 0, usuario: n ? await usuarioAtual(req, env) : null });
  }

  // primeiro acesso: cria o administrador
  if (p === "/api/setup" && m === "POST") {
    const b = await corpo(req);
    b.usuario = limparUsuario(b.usuario);
    validarUsuario(b.usuario); validarSenha(b.senha);
    const nome = String(b.nome || "").trim(); if (!nome) falha("Informe o nome.");
    if ((await contarUsuarios(env)) > 0) falha("O administrador já foi criado. Entre com usuário e senha.", 409);
    const salt = aleatorio(); const h = await hashSenha(b.senha, salt);
    const r = await env.DB.prepare("INSERT INTO usuarios (usuario,nome,senha_hash,salt,admin,ativo,criado) VALUES (?,?,?,?,1,1,?)").bind(b.usuario.trim(), nome, h, salt, agora()).run();
    const token = await criarSessao(env, r.meta.last_row_id);
    return json({ ok: true }, 200, { "set-cookie": cookieSessao(token, SESSAO_DIAS * 86400) });
  }

  if (p === "/api/login" && m === "POST") {
    const b = await corpo(req);
    const u = await env.DB.prepare("SELECT * FROM usuarios WHERE usuario=?").bind(limparUsuario(b.usuario)).first();
    const h = u ? await hashSenha(String(b.senha || ""), u.salt) : await hashSenha("x", "x");
    if (!u || !iguais(h, u.senha_hash)) falha("Usuário ou senha incorretos.", 401);
    if (!u.ativo) falha("Este usuário está desativado. Fale com o administrador.", 403);
    const token = await criarSessao(env, u.id);
    return json({ ok: true }, 200, { "set-cookie": cookieSessao(token, SESSAO_DIAS * 86400) });
  }

  if (p === "/api/logout" && m === "POST") {
    const token = lerCookie(req, "sessao");
    if (token) await env.DB.prepare("DELETE FROM sessoes WHERE token=?").bind(token).run();
    return json({ ok: true }, 200, { "set-cookie": cookieSessao("", 0) });
  }

  // trocar a própria senha
  if (p === "/api/senha" && m === "POST") {
    const eu = await exigirLogin(req, env);
    const b = await corpo(req); validarSenha(b.nova);
    const u = await env.DB.prepare("SELECT * FROM usuarios WHERE id=?").bind(eu.id).first();
    if (!iguais(await hashSenha(String(b.atual || ""), u.salt), u.senha_hash)) falha("A senha atual não confere.", 400);
    const salt = aleatorio(); const h = await hashSenha(b.nova, salt);
    await env.DB.prepare("UPDATE usuarios SET senha_hash=?, salt=? WHERE id=?").bind(h, salt, eu.id).run();
    return json({ ok: true });
  }

  /* ----- usuários (admin) ----- */
  if (seg[0] === "usuarios") {
    const eu0 = await exigirLogin(req, env);
    if (!eu0.admin && !(m === "PUT" && Number(seg[1]) === eu0.id)) falha("Apenas administradores podem fazer isso.", 403);
    const eu = eu0;
    if (seg.length === 1 && m === "GET") {
      const r = await env.DB.prepare("SELECT id,usuario,nome,admin,ativo,criado FROM usuarios ORDER BY nome COLLATE NOCASE").all();
      return json(r.results.map((x) => ({ ...x, admin: !!x.admin, ativo: !!x.ativo })));
    }
    if (seg.length === 1 && m === "POST") {
      const b = await corpo(req);
      b.usuario = limparUsuario(b.usuario);
      validarUsuario(b.usuario); validarSenha(b.senha);
      const nome = String(b.nome || "").trim(); if (!nome) falha("Informe o nome.");
      const salt = aleatorio(); const h = await hashSenha(b.senha, salt);
      try {
        await env.DB.prepare("INSERT INTO usuarios (usuario,nome,senha_hash,salt,admin,ativo,criado) VALUES (?,?,?,?,?,1,?)").bind(b.usuario.trim(), nome, h, salt, b.admin ? 1 : 0, agora()).run();
      } catch (e) { if (String(e).includes("UNIQUE")) falha("Já existe um usuário com esse nome de acesso.", 409); throw e; }
      return json({ ok: true });
    }
    const id = Number(seg[1]);
    if (!id) falha("Usuário não encontrado.", 404);
    if (m === "PUT") {
      const b = await corpo(req);
      if (!eu.admin) { delete b.admin; delete b.ativo; delete b.senha; } // quem não é admin só muda o próprio nome e usuário
      const alvo = await env.DB.prepare("SELECT * FROM usuarios WHERE id=?").bind(id).first();
      if (!alvo) falha("Usuário não encontrado.", 404);
      if (id === eu.id && (b.admin === false || b.ativo === false)) falha("Você não pode tirar o seu próprio acesso de administrador nem se desativar.");
      const sets = [], vals = [];
      if (typeof b.nome === "string") { if (!b.nome.trim()) falha("Informe o nome."); sets.push("nome=?"); vals.push(b.nome.trim()); }
      if (typeof b.usuario === "string") { const u = limparUsuario(b.usuario); validarUsuario(u); sets.push("usuario=?"); vals.push(u); }
      if (typeof b.admin === "boolean") { sets.push("admin=?"); vals.push(b.admin ? 1 : 0); }
      if (typeof b.ativo === "boolean") { sets.push("ativo=?"); vals.push(b.ativo ? 1 : 0); }
      if (b.senha) { validarSenha(b.senha); const salt = aleatorio(); sets.push("senha_hash=?", "salt=?"); vals.push(await hashSenha(b.senha, salt), salt); }
      if (!sets.length) return json({ ok: true });
      const st = [env.DB.prepare(`UPDATE usuarios SET ${sets.join(",")} WHERE id=?`).bind(...vals, id)];
      if (b.ativo === false || b.senha) st.push(env.DB.prepare("DELETE FROM sessoes WHERE usuario_id=?").bind(id));
      try { await env.DB.batch(st); }
      catch (e) { if (String(e).includes("UNIQUE")) falha("Já existe um usuário com esse nome de acesso.", 409); throw e; }
      return json({ ok: true });
    }
    if (m === "DELETE") {
      if (id === eu.id) falha("Você não pode excluir o seu próprio usuário.");
      await env.DB.batch([
        env.DB.prepare("DELETE FROM sessoes WHERE usuario_id=?").bind(id),
        env.DB.prepare("DELETE FROM usuarios WHERE id=?").bind(id),
      ]);
      return json({ ok: true });
    }
  }

  /* ----- check-lists ----- */
  if (seg[0] === "checklists") {
    const eu = await exigirLogin(req, env);
    if (seg.length === 1 && m === "GET") {
      const r = await env.DB.prepare(
        "SELECT c.id,c.dados,c.atualizado,u1.nome AS criado_por_nome,u2.nome AS atualizado_por_nome FROM checklists c LEFT JOIN usuarios u1 ON u1.id=c.criado_por LEFT JOIN usuarios u2 ON u2.id=c.atualizado_por ORDER BY c.atualizado DESC"
      ).all();
      return json(r.results.map((x) => ({ ...JSON.parse(x.dados), id: x.id, updatedAt: x.atualizado, _criadoPor: x.criado_por_nome || "", _atualizadoPor: x.atualizado_por_nome || "" })));
    }
    const id = seg[1];
    if (!id || !/^[\w-]{3,64}$/.test(id)) falha("Check-list não encontrado.", 404);
    if (m === "GET") {
      const x = await env.DB.prepare("SELECT dados,atualizado FROM checklists WHERE id=?").bind(id).first();
      if (!x) falha("Check-list não encontrado.", 404);
      return json({ ...JSON.parse(x.dados), id, updatedAt: x.atualizado });
    }
    if (m === "PUT") {
      const c = await corpo(req);
      if (!c || typeof c !== "object") falha("Dados inválidos.");
      delete c._criadoPor; delete c._atualizadoPor;
      c.id = id;
      const dados = JSON.stringify(c);
      if (dados.length > 1_800_000) falha("O check-list ficou grande demais para salvar. Reduza o croqui ou as assinaturas.", 413);
      const t = agora();
      await env.DB.prepare(
        `INSERT INTO checklists (id,dados,cliente,cidade,status,criado_por,criado,atualizado,atualizado_por) VALUES (?,?,?,?,?,?,?,?,?)
         ON CONFLICT(id) DO UPDATE SET dados=excluded.dados, cliente=excluded.cliente, cidade=excluded.cidade, status=excluded.status, atualizado=excluded.atualizado, atualizado_por=excluded.atualizado_por`
      ).bind(id, dados, c.cliente || "", c.cidade || "", c.status || "andamento", eu.id, t, t, eu.id).run();
      return json({ ok: true, updatedAt: t });
    }
    if (m === "DELETE") {
      await env.DB.batch([
        env.DB.prepare("DELETE FROM fotos WHERE checklist_id=?").bind(id),
        env.DB.prepare("DELETE FROM checklists WHERE id=?").bind(id),
      ]);
      return json({ ok: true });
    }
  }

  /* ----- fotos ----- */
  if (seg[0] === "fotos") {
    await exigirLogin(req, env);
    if (seg.length === 1 && m === "POST") {
      const checklist = url.searchParams.get("checklist") || "";
      const item = url.searchParams.get("item") || "";
      if (!/^[\w-]{3,64}$/.test(checklist)) falha("Check-list inválido.");
      const mime = (req.headers.get("content-type") || "").split(";")[0].trim();
      if (!/^image\/(jpeg|png|webp)$/.test(mime)) falha("Envie a foto em JPG, PNG ou WEBP.");
      const buf = await req.arrayBuffer();
      if (!buf.byteLength) falha("Foto vazia.");
      if (buf.byteLength > FOTO_MAX) falha("Foto grande demais.", 413);
      const id = "f_" + aleatorio(12);
      await env.DB.prepare("INSERT INTO fotos (id,checklist_id,item_id,mime,dados,tamanho,criado) VALUES (?,?,?,?,?,?,?)").bind(id, checklist, item, mime, buf, buf.byteLength, agora()).run();
      return json({ id, sizeBytes: buf.byteLength });
    }
    const id = seg[1];
    if (!id || !/^f_[0-9a-f]{24}$/.test(id)) falha("Foto não encontrada.", 404);
    if (m === "GET") {
      const f = await env.DB.prepare("SELECT mime,dados FROM fotos WHERE id=?").bind(id).first();
      if (!f) falha("Foto não encontrada.", 404);
      const bytes = f.dados instanceof ArrayBuffer ? f.dados : new Uint8Array(f.dados);
      return new Response(bytes, { headers: { "content-type": f.mime, "cache-control": "private, max-age=31536000, immutable" } });
    }
    if (m === "DELETE") {
      await env.DB.prepare("DELETE FROM fotos WHERE id=?").bind(id).run();
      return json({ ok: true });
    }
  }

  return json({ erro: "Rota não encontrada." }, 404);
}
