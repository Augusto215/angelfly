// server.js (versão atualizada: logs detalhados + suporte WEBHOOK driver + tratamento resposta n8n vazia)
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

// IMPORTANTE: usar a SERVICE ROLE KEY do Supabase no servidor
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const N8N_RECEBER_DATA_URL =
  process.env.N8N_RECEBER_DATA_URL ||
  "https://n8n.srv942429.hstgr.cloud/webhook/receber-data";

const N8N_DRIVER_URL =
  process.env.N8N_DRIVER_URL ||
  "https://n8n.srv942429.hstgr.cloud/webhook/driver";

console.log("🔗 N8N restaurant webhook:", N8N_RECEBER_DATA_URL);
console.log("🔗 N8N driver webhook:", N8N_DRIVER_URL);

// ----------------------
// Helpers
// ----------------------
function generateRandomPassword(len = 16) {
  return crypto.randomBytes(len).toString("base64").slice(0, len);
}

function isValidYYYYMM(s) {
  return typeof s === "string" && /^\d{4}-(0[1-9]|1[0-2])$/.test(s);
}

function normalizeN8nResponse(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  if (data?.items && Array.isArray(data.items)) return data.items;
  if (data?.object === "page") return [data];
  if (data?.json?.object === "page") return [data.json];
  return [];
}

function resolveMatchId(profile) {
  return (
    profile?.restaurant_match_id ||
    profile?.driver_match_id ||
    profile?.match_id ||
    profile?.restaurant_id ||
    profile?.driver_id ||
    null
  );
}

// calcula semana (startDay: 0=domingo .. 1=segunda .. 6=sabado) a partir de uma data ISO (YYYY-MM-DD) ou hoje
function computeWeekRangeFromDate(dateIso = null, startDay = 1) {
  const d = dateIso ? new Date(dateIso + "T00:00:00") : new Date();
  // normalize time
  d.setHours(0, 0, 0, 0);
  const dow = d.getDay(); // 0..6
  // distance from startDay to current dow
  let diff = dow - startDay;
  if (diff < 0) diff += 7;
  const start = new Date(d);
  start.setDate(d.getDate() - diff);
  start.setHours(0, 0, 0, 0);

  const end = new Date(start);
  end.setDate(start.getDate() + 6);
  end.setHours(23, 59, 59, 999);

  const isoStart = start.toISOString().slice(0, 10);
  const isoEnd = end.toISOString().slice(0, 10);
  return { week_start: isoStart, week_end: isoEnd };
}

// Node fetch fallback (server-side)
async function safeFetch(url, options) {
  if (typeof fetch !== "undefined") return fetch(url, options);
  const mod = await import("node-fetch");
  return mod.default(url, options);
}

// ----------------------
// Middleware
// ----------------------
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || true,
    credentials: true,
  })
);

app.use(bodyParser.json({ limit: "2mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// LOGGER GLOBAL (muito verboso para debugging)
app.use((req, res, next) => {
  const start = Date.now();
  console.log(`\n➡️  ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length) {
    try {
      console.log("  • Body:", JSON.stringify(req.body, null, 2));
    } catch (e) {
      console.log("  • Body: <unserializable>");
    }
  }
  res.on("finish", () => {
    const ms = Date.now() - start;
    console.log(`⬅️  ${req.method} ${req.url} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "lax",
    },
  })
);

const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    console.log("🔒 requireAuth bloqueou. Session atual:", JSON.stringify(req.session, null, 2));
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Authentication required" });
  }
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
};

// ----------------------
// API Routes
// ----------------------
app.post("/api/login", async (req, res) => {
  console.log("✅ BATEU NO /api/login");
  try {
    const { email, password, category } = req.body;

    const { data: authData, error: authError } =
      await supabase.auth.signInWithPassword({ email, password });

    if (authError || !authData?.user) {
      console.log("❌ LOGIN FALHOU:", authError?.message);
      return res.status(401).json({
        error: authError?.message || "Invalid credentials",
      });
    }

    const { data: profileData, error: profileError } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("id", authData.user.id)
      .single();

    console.log("profileData:", profileData);
    console.log("profileError:", profileError);

    if (profileError || !profileData) {
      return res
        .status(401)
        .json({ error: "User profile not found in user_profiles" });
    }

    // valida categoria se veio
    if (
      category &&
      profileData.user_role !== category &&
      profileData.user_role !== "admin"
    ) {
      await supabase.auth.signOut();
      return res.status(401).json({ error: "Invalid user category" });
    }

    req.session.user = {
      id: authData.user.id,
      email: authData.user.email,
      role: profileData.user_role,
      name: profileData.full_name || authData.user.email,
    };

    let redirect = "/dashboard";
    if (profileData.user_role === "driver") redirect = "/dashboard-driver";
    if (profileData.user_role === "admin") redirect = "/admin";

    return res.json({
      success: true,
      user: req.session.user,
      redirect,
    });
  } catch (error) {
    console.error("🔥 ERRO NO LOGIN:", error && error.stack ? error.stack : error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/user", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// GET user by ID
app.get("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const { data, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("id", userId)
      .single();

    if (error) {
      console.error("❌ /api/admin/users/:id (GET) error:", error);
      // Pode ser 404 se não for encontrado
      if (error.code === 'PGRST116') { 
         return res.status(404).json({ error: "User profile not found" });
      }
      return res.status(400).json({ error: error.message });
    }

    // Nota: O Supabase não retorna o campo 'email' na tabela user_profiles.
    // Para o frontend, precisamos do email. Vamos buscar no Auth.
    const { data: authData, error: authError } =
        await supabase.auth.admin.getUserById(userId);
    
    // Se o profile existe mas o auth falhou/não existe, ainda retornamos o profile, mas com um aviso.
    if (authError || !authData?.user) {
        console.warn(`⚠️ Auth user not found for profile ID: ${userId}`);
    }

    const userWithEmail = {
        ...data,
        email: authData?.user?.email || '[Auth Email Missing]',
        // Adicionando um campo de verificação de atividade (se você tiver no auth)
        is_active: data.is_active, 
    };

    return res.json(userWithEmail);
  } catch (e) {
    console.error("🔥 /api/admin/users/:id (GET) error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/user/context", requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;

    const { data: profile, error } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("id", userId)
      .single();

    console.log("📌 /api/user/context profile:", profile);
    console.log("📌 /api/user/context error:", error);

    if (error || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    const matchId = resolveMatchId(profile);
    const role = profile.user_role || req.session.user.role;

    const baseUser = {
      id: profile.id,
      email: req.session.user.email,
      role,
      name: profile.full_name || req.session.user.email,
    };

    const weekStartDay =
      typeof profile.week_start_day === "number"
        ? profile.week_start_day
        : null;

    if (role === "driver") {
      return res.json({
        user: baseUser,
        driver: {
          driver_match_id: matchId,
          driver_name: profile.full_name || profile.driver_name || null,
        },
      });
    }

    return res.json({
      user: baseUser,
      restaurant: {
        restaurant_match_id: matchId,
        restaurant_name:
          profile.restaurant_name || profile.full_name || null,
        week_start_day: weekStartDay,
      },
    });
  } catch (e) {
    console.error("🔥 /api/user/context error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * /api/report/month
 * Recebe body { month: "YYYY-MM", week_start?: "YYYY-MM-DD", week_end?: "YYYY-MM-DD" }
 * Decide automaticamente qual webhook chamar (restaurant vs driver) baseado no profile.user_role.
 * - Se n8n retornar body vazio -> tratamos como [] (não quebrar).
 * - Se n8n retornar não-2xx -> repassamos erro 502 com preview do raw.
 */
app.post("/api/report/month", requireAuth, async (req, res) => {
  try {
    const { month, week_start, week_end } = req.body;
    console.log("📌 /api/report/month body:", JSON.stringify(req.body, null, 2));

    if (!isValidYYYYMM(month)) {
      console.log("❌ month inválido recebido:", month);
      return res.status(400).json({ error: "month inválido (use YYYY-MM)" });
    }

    const userId = req.session.user.id;

    const { data: profile, error: profileError } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("id", userId)
      .single();

    console.log("📌 profile p/ report:", profile);
    console.log("📌 profileError p/ report:", profileError);

    if (profileError || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    const matchId = resolveMatchId(profile);

    if (!matchId) {
      console.log("❌ matchId não encontrado para profile:", profile);
      return res.status(404).json({
        error:
          "match_id / restaurant_match_id não encontrado para usuário logado",
      });
    }

    // Se week_start/week_end não vierem, calcula automaticamente (para driver = segunda-domingo por padrão)
    let finalWeekStart = week_start;
    let finalWeekEnd = week_end;
    if (!finalWeekStart || !finalWeekEnd) {
      // preferir week_start_day do profile se existir (para restaurants pode ter configurado)
      const profileStartDay = typeof profile.week_start_day === "number" ? profile.week_start_day : null;
      // para drivers queremos forçar segunda(1) por pedido do usuário
      const defaultStartDay = profile.user_role === "driver" ? 1 : (profileStartDay ?? 1);
      const range = computeWeekRangeFromDate(null, defaultStartDay);
      finalWeekStart = finalWeekStart || range.week_start;
      finalWeekEnd = finalWeekEnd || range.week_end;
      console.log(`   • computed week range -> start:${finalWeekStart} end:${finalWeekEnd} (startDay=${defaultStartDay})`);
    }

    // Monta payload
    const payload = {
      month,
      restaurant_match_id: matchId,
      role: profile.user_role || req.session.user.role,
      week_start: finalWeekStart,
      week_end: finalWeekEnd,
    };

    // decide URL conforme role (driver -> N8N_DRIVER_URL)
    const role = profile.user_role || req.session.user.role;
    const sendURL = role === "driver" ? N8N_DRIVER_URL : N8N_RECEBER_DATA_URL;

    console.log("➡️ Enviando p/ n8n URL:", sendURL);
    console.log("   • payload:", JSON.stringify(payload, null, 2));

    // Faz o fetch com tratamento detalhado
    let n8nRes;
    try {
      n8nRes = await safeFetch(sendURL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (fetchErr) {
      console.error("🔥 Erro no fetch para n8n:", fetchErr && fetchErr.stack ? fetchErr.stack : fetchErr);
      return res.status(502).json({ error: "Erro ao conectar n8n (fetch failed)", details: String(fetchErr) });
    }

    // Log do status/headers
    try {
      console.log("⬅️ n8n response status:", n8nRes.status, n8nRes.statusText || "");
      const contentType = n8nRes.headers && n8nRes.headers.get ? n8nRes.headers.get("content-type") : "unknown";
      console.log("   • n8n content-type:", contentType);
    } catch (hdrErr) {
      console.warn("⚠️ Não foi possível ler headers do n8n response:", hdrErr);
    }

    // Lê o corpo (texto) e loga parte dele
    let text;
    try {
      text = await n8nRes.text();
    } catch (readErr) {
      console.error("🔥 Erro ao ler corpo da resposta do n8n:", readErr && readErr.stack ? readErr.stack : readErr);
      return res.status(502).json({ error: "Erro ao ler resposta do n8n", details: String(readErr) });
    }

    console.log("   • n8n response length:", text ? text.length : 0);
    console.log("   • n8n response preview (first 8k chars):", (text || "").slice(0, 8000));

    // Se n8n retornou HTTP diferente de 2xx, repassamos info para cliente
    if (!n8nRes.ok) {
      console.error("❌ n8n respondeu com status não OK:", n8nRes.status);
      return res.status(502).json({
        error: "Bad gateway - n8n retornou erro",
        status: n8nRes.status,
        statusText: n8nRes.statusText,
        raw: (text || "").slice(0, 10000)
      });
    }

    // Se corpo for vazio, tratamos como [] (isso resolve seu erro Unexpected end of JSON input)
    if (!text || text.trim().length === 0) {
      console.log("ℹ️ n8n retornou body vazio — interpretando como lista vazia []");
      return res.json([]);
    }

    // tenta parsear JSON — se falhar, retorne 502 com raw para debug
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      console.error("❌ Resposta do n8n não é JSON válido:", e);
      return res
        .status(502)
        .json({ error: "Resposta inválida do n8n (não JSON)", raw: (text || "").slice(0, 10000) });
    }

    const items = normalizeN8nResponse(data);
    console.log("✅ Itens normalizados (n8n):", items.length);

    return res.json(items);
  } catch (e) {
    console.error("🔥 /api/report/month error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// =========================
// ADMIN: USERS CRUD (mantido como estava)
// =========================

// CREATE user
app.post("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const {
      email,
      user_role,
      full_name,
      phone_number,
      business_address, // opcional, pode vir undefined
      match_id,
      week_start_day,
      week_end_day,
      is_active,
      password, // opcional
    } = req.body;

    if (!email || !user_role || !full_name) {
      return res.status(400).json({
        error: "Campos obrigatórios: email, user_role, full_name",
      });
    }

    const weekStart =
      week_start_day === null ||
      week_start_day === undefined ||
      week_start_day === ""
        ? null
        : Number(week_start_day);
    const weekEnd =
      week_end_day === null || week_end_day === undefined || week_end_day === ""
        ? null
        : Number(week_end_day);

    const active =
      typeof is_active === "boolean"
        ? is_active
        : is_active === "false"
        ? false
        : true;

    const finalPassword =
      typeof password === "string" && password.trim().length >= 6
        ? password.trim()
        : generateRandomPassword(16);

    const { data: createdUser, error: createAuthError } =
      await supabase.auth.admin.createUser({
        email,
        password: finalPassword,
        email_confirm: true,
      });

    if (createAuthError || !createdUser?.user) {
      console.error("❌ Erro ao criar user no Auth:", createAuthError);
      return res.status(400).json({
        error: createAuthError?.message || "Erro ao criar usuário no Auth",
      });
    }

    const authUser = createdUser.user;

    const profileRow = {
      id: authUser.id,
      user_role,
      full_name,
      phone_number: phone_number || null,
      business_address: business_address || null,
      is_active: active,
      match_id: match_id || null,
      week_start_day: weekStart,
      week_end_day: weekEnd,
    };

    // upsert pra não estourar PK se já existir profile com esse id
    const { data: profileInsert, error: profileError } = await supabase
      .from("user_profiles")
      .upsert([profileRow], { onConflict: "id" })
      .select()
      .single();

    if (profileError) {
      console.error("❌ Erro ao salvar em user_profiles:", profileError);
      return res.status(400).json({
        error: "Erro ao salvar user_profiles",
        details: profileError.message,
      });
    }

    console.log("✅ Usuário criado/atualizado com sucesso:", {
      auth_id: authUser.id,
      email: authUser.email,
      role: user_role,
    });

    return res.status(201).json({
      success: true,
      user: {
        id: authUser.id,
        email: authUser.email,
        password: finalPassword, // senha usada (digitada ou random)
        role: user_role,
        profile: profileInsert,
      },
    });
  } catch (e) {
    console.error("🔥 /api/admin/users (POST) error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// LIST users - AGORA COM EMAIL DO SUPABASE AUTH
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 50);
    const offset = (page - 1) * limit;
    const roleFilter = req.query.role || null;

    let query = supabase
      .from("user_profiles")
      .select("*", { count: "exact" })
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (roleFilter) {
      query = query.eq("user_role", roleFilter);
    }

    const { data: profiles, error, count } = await query;

    if (error) {
      console.error("❌ /api/admin/users (GET) error:", error);
      return res.status(400).json({ error: error.message });
    }

    if (!profiles || profiles.length === 0) {
      return res.json({
        items: [],
        page,
        limit,
        total: count || 0,
      });
    }

    // --- CORREÇÃO: Busca os emails de cada usuário no Auth ---
    // Cria um mapa para armazenar o email de cada profile ID
    const userEmailsMap = {};
    const profilesToFetch = profiles.map(p => p.id);
    
    // NOTA: O método listUsers() do Supabase Admin SDK não é ideal para paginação, 
    // mas vamos tentar buscar todos os IDs da lista atual para preencher os emails.

    // Isso pode ser muito lento ou falhar se você tiver milhares de usuários
    // e o Supabase Auth limitar a consulta. Para esta solução simples, vamos iterar.

    const usersWithEmailPromises = profiles.map(async (profile) => {
        try {
            const { data: authData } = await supabase.auth.admin.getUserById(profile.id);
            return {
                ...profile,
                email: authData?.user?.email || '[Auth Email Missing]',
                // Anexa o email ao objeto do perfil
            };
        } catch (e) {
            console.error(`Falha ao buscar Auth para user ID ${profile.id}:`, e);
            return {
                ...profile,
                email: '[Auth Error]',
            };
        }
    });

    const itemsWithEmail = await Promise.all(usersWithEmailPromises);
    // ---------------------------------------------------------

    return res.json({
      items: itemsWithEmail || [],
      page,
      limit,
      total: count || 0,
    });
  } catch (e) {
    console.error("🔥 /api/admin/users (GET) error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// UPDATE user
app.put("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const {
      email,
      password,
      user_role,
      full_name,
      phone_number,
      business_address,
      match_id,
      week_start_day,
      week_end_day,
      is_active,
    } = req.body;

    // 1) atualiza Auth se necessário
    if (email || password) {
      const updatePayload = {};
      if (email) updatePayload.email = email;
      if (password && password.trim().length >= 6) {
        updatePayload.password = password.trim();
      }

      if (Object.keys(updatePayload).length) {
        const { error: authUpdateError } =
          await supabase.auth.admin.updateUserById(userId, updatePayload);

        if (authUpdateError) {
          console.error("❌ Erro ao atualizar Auth user:", authUpdateError);
          return res.status(400).json({
            error:
              authUpdateError.message ||
              "Erro ao atualizar dados de autenticação",
          });
        }
      }
    }

    // 2) atualiza profile
    const profileUpdate = {};
    if (user_role !== undefined) profileUpdate.user_role = user_role;
    if (full_name !== undefined) profileUpdate.full_name = full_name;
    if (phone_number !== undefined) profileUpdate.phone_number = phone_number;
    if (business_address !== undefined)
      profileUpdate.business_address = business_address;
    if (match_id !== undefined) profileUpdate.match_id = match_id;

    if (week_start_day !== undefined && week_start_day !== "") {
      profileUpdate.week_start_day = Number(week_start_day);
    } else if (week_start_day === "") {
      profileUpdate.week_start_day = null;
    }

    if (week_end_day !== undefined && week_end_day !== "") {
      profileUpdate.week_end_day = Number(week_end_day);
    } else if (week_end_day === "") {
      profileUpdate.week_end_day = null;
    }

    if (is_active !== undefined) {
      profileUpdate.is_active =
        typeof is_active === "boolean"
          ? is_active
          : is_active === "false"
          ? false
          : true;
    }

    if (Object.keys(profileUpdate).length === 0) {
      return res.json({ success: true, message: "Nada para atualizar" });
    }

    const { data, error } = await supabase
      .from("user_profiles")
      .update(profileUpdate)
      .eq("id", userId)
      .select()
      .single();

    if (error) {
      console.error("❌ Erro ao atualizar user_profiles:", error);
      return res.status(400).json({ error: error.message });
    }

    return res.json({
      success: true,
      profile: data,
    });
  } catch (e) {
    console.error("🔥 /api/admin/users/:id (PUT) error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// DELETE user
app.delete("/api/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    // apaga profile
    const { error: profileError } = await supabase
      .from("user_profiles")
      .delete()
      .eq("id", userId);

    if (profileError) {
      console.error("❌ Erro ao deletar user_profiles:", profileError);
      return res.status(400).json({ error: profileError.message });
    }

    // apaga do Auth
    const { error: authError } = await supabase.auth.admin.deleteUser(userId);

    if (authError) {
      console.error("❌ Erro ao deletar user no Auth:", authError);
      return res.status(400).json({ error: authError.message });
    }

    return res.json({ success: true });
  } catch (e) {
    console.error("🔥 /api/admin/users/:id (DELETE) error:", e && e.stack ? e.stack : e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ----------------------
// Logout
// ----------------------
app.post("/api/logout", async (req, res) => {
  try {
    await supabase.auth.signOut();
    req.session.destroy(() => {});
    res.json({ success: true, redirect: "/login-restaurant.html" });
  } catch (error) {
    res.status(500).json({ error: "Logout failed" });
  }
});

// ----------------------
// Page Routes
// ----------------------
app.get("/", (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === "driver") return res.redirect("/dashboard-driver");
    if (req.session.user.role === "admin") return res.redirect("/admin");
    return res.redirect("/dashboard");
  }
  return res.redirect("/login-restaurant");
});

app.get("/login-driver", (req, res) => {
  if (req.session.user && req.session.user.role === "driver") {
    return res.redirect("/dashboard-driver");
  }
  return res.sendFile(path.join(PUBLIC_DIR, "login-driver.html"));
});

app.get("/login-restaurant", (req, res) => {
  if (req.session.user && req.session.user.role === "restaurant") {
    return res.redirect("/dashboard");
  }
  if (req.session.user && req.session.user.role === "admin") {
    return res.redirect("/admin");
  }
  return res.sendFile(path.join(PUBLIC_DIR, "login-restaurant.html"));
});

app.get("/login-admin", (req, res) => {
  if (req.session.user && req.session.user.role === "admin") {
    return res.redirect("/admin");
  }
  return res.sendFile(path.join(PUBLIC_DIR, "login-admin.html"));
});

app.get("/dashboard", requireAuth, (req, res) => {
  if (
    req.session.user.role !== "restaurant" &&
    req.session.user.role !== "admin"
  ) {
    return res.status(403).send("Forbidden");
  }
  res.sendFile(path.join(PUBLIC_DIR, "dashboard.html"));
});

app.get("/dashboard.html", requireAuth, (req, res) => {
  if (
    req.session.user.role !== "restaurant" &&
    req.session.user.role !== "admin"
  ) {
    return res.status(403).send("Forbidden");
  }
  res.sendFile(path.join(PUBLIC_DIR, "dashboard.html"));
});

app.get("/dashboard-driver", requireAuth, (req, res) => {
  if (req.session.user.role !== "driver") {
    return res.status(403).send("Forbidden");
  }
  res.sendFile(path.join(PUBLIC_DIR, "dashboard-driver.html"));
});

app.get("/dashboard-driver.html", requireAuth, (req, res) => {
  if (req.session.user.role !== "driver") {
    return res.status(403).send("Forbidden");
  }
  res.sendFile(path.join(PUBLIC_DIR, "dashboard-driver.html"));
});

app.get("/admin", requireAdmin, (req, res) => {
  return res.sendFile(path.join(PUBLIC_DIR, "admin.html"));
});

app.get("/create-user", requireAdmin, (req, res) => {
  return res.sendFile(path.join(PUBLIC_DIR, "create-user.html"));
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// Global error
app.use((err, req, res, next) => {
  console.error("🔥 ERRO GLOBAL NÃO CAPTURADO:", err && err.stack ? err.stack : err);
  res.status(500).json({ error: "Unhandled server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;
