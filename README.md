# Check-List de Cadastro PPCI — JG2 Engenharia e Arquitetura

App para preencher em campo o check-list de cadastro arquitetônico PPCI, com fotos, croqui, assinaturas e PDF.

- **Hospedagem:** Cloudflare Worker `checklist-ppci`, que serve a página e a API.
- **Banco:** D1 `checklist_ppci`, com usuários, sessões, check-lists e fotos. O banco já foi criado e já tem as tabelas.
- **Login:** usuário e senha. No primeiro acesso, o app pede para criar o administrador.

## Estrutura

```
public/index.html   página do app
public/icons/       ícones (aba do navegador e tela inicial do celular)
public/manifest.webmanifest  permite instalar o app no celular
src/index.js        API (/api/...)
wrangler.jsonc      configuração do Worker e ligação com o banco D1
schema.sql          tabelas do banco (já aplicadas)
```

## Publicar (uma única vez)

1. No GitHub, crie o repositório vazio `checklist-ppci` e envie estes arquivos.
2. Na Cloudflare, vá em **Workers & Pages → Create → Import a repository** e escolha `checklist-ppci`.
   - Project name: `checklist-ppci` (precisa ser igual ao `name` do wrangler.jsonc)
   - Build command: deixe vazio
   - Deploy command: `npx wrangler deploy`
3. Clique em **Deploy**. Quando terminar, abra o endereço `https://checklist-ppci.<sua-conta>.workers.dev` e crie o administrador.

A partir daí, toda alteração enviada ao GitHub é publicada sozinha.

## Rotas da API

| Rota | O que faz |
|---|---|
| `GET /api/estado` | Diz se precisa criar o admin e quem está logado |
| `POST /api/setup` | Cria o primeiro administrador |
| `POST /api/login`, `POST /api/logout` | Entrar e sair |
| `POST /api/senha` | Trocar a própria senha |
| `GET/POST /api/usuarios`, `PUT/DELETE /api/usuarios/:id` | Equipe (só admin) |
| `GET /api/checklists`, `GET/PUT/DELETE /api/checklists/:id` | Check-lists |
| `POST /api/fotos?checklist=..&item=..`, `GET/DELETE /api/fotos/:id` | Fotos (guardadas no D1) |
