const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bodyParser = require("body-parser");
const path = require("path");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

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

// ----------------------
// Middleware
// ----------------------
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || true,
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// ✅ LOGGER GLOBAL
app.use((req, res, next) => {
  const start = Date.now();
  console.log(`\n➡️  ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length) {
    console.log("Body:", req.body);
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
    console.log("🔒 requireAuth bloqueou. Session atual:", req.session);
    return res.status(401).json({ error: "Authentication required" });
  }
  next();
};

// fetch compat (caso Node antigo)
async function safeFetch(url, options) {
  if (typeof fetch !== "undefined") return fetch(url, options);
  const mod = await import("node-fetch");
  return mod.default(url, options);
}

// valida YYYY-MM
function isValidYYYYMM(s) {
  return typeof s === "string" && /^\d{4}-(0[1-9]|1[0-2])$/.test(s);
}

// normaliza resposta do n8n -> SEMPRE array
function normalizeN8nResponse(data) {
  if (Array.isArray(data)) return data;
  if (data?.items && Array.isArray(data.items)) return data.items;
  if (data?.object === "page") return [data];
  if (data?.json?.object === "page") return [data.json];
  return [];
}

// helper: resolve match id com fallback
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

// ----------------------
// Routes
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

    // ✅ valida categoria se veio no body
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

    // ✅ redirect dinâmico
    let redirect = "/dashboard";
    if (profileData.user_role === "driver") redirect = "/dashboard-driver";
    if (profileData.user_role === "admin") redirect = "/dashboard";

    return res.json({
      success: true,
      user: req.session.user,
      redirect,
    });
  } catch (error) {
    console.error("🔥 ERRO NO LOGIN:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Current user
app.get("/api/user", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// ✅ Contexto do usuário (role + match_id)
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

    // ✅ não quebra o front do restaurant
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
          profile.restaurant_name ||
          profile.full_name ||
          null,
      },
    });
  } catch (e) {
    console.error("🔥 /api/user/context error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Relatório mensal RESTAURANT
app.post("/api/report/month", requireAuth, async (req, res) => {
  try {
    const { month } = req.body;
    console.log("📌 /api/report/month body:", req.body);

    if (!isValidYYYYMM(month)) {
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
      return res.status(404).json({
        error: "match_id / restaurant_match_id não encontrado para usuário logado",
      });
    }

    const payload = {
      month,
      restaurant_match_id: matchId,
      role: profile.user_role || req.session.user.role,
    };

    console.log("➡️ Enviando p/ n8n (restaurant):", payload);

    const n8nRes = await safeFetch(N8N_RECEBER_DATA_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const text = await n8nRes.text();
    console.log("⬅️ Resposta crua n8n (até 1200 chars):", text.slice(0, 1200));

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      return res.status(502).json({ error: "Resposta inválida do n8n", raw: text });
    }

    const items = normalizeN8nResponse(data);
    console.log("✅ Itens normalizados (restaurant):", items.length);

    return res.json(items);
  } catch (e) {
    console.error("🔥 /api/report/month error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ Relatório mensal DRIVER
app.post("/api/report/driver/month", requireAuth, async (req, res) => {
  try {
    const { month } = req.body;
    console.log("📌 /api/report/driver/month body:", req.body);

    if (!isValidYYYYMM(month)) {
      return res.status(400).json({ error: "month inválido (use YYYY-MM)" });
    }

    const userId = req.session.user.id;

    const { data: profile, error: profileError } = await supabase
      .from("user_profiles")
      .select("*")
      .eq("id", userId)
      .single();

    console.log("📌 profile p/ driver report:", profile);
    console.log("📌 profileError p/ driver report:", profileError);

    if (profileError || !profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    const matchId = resolveMatchId(profile);

    if (!matchId) {
      return res.status(404).json({
        error: "match_id / driver_match_id não encontrado para usuário logado",
      });
    }

    const payload = {
      month,
      driver_match_id: matchId,
      role: "driver",
    };

    console.log("➡️ Enviando p/ n8n (driver):", payload);

    const n8nRes = await safeFetch(N8N_DRIVER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const text = await n8nRes.text();
    console.log("⬅️ Resposta crua n8n DRIVER (até 1200 chars):", text.slice(0, 1200));

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      return res.status(502).json({ error: "Resposta inválida do n8n (driver)", raw: text });
    }

    const items = normalizeN8nResponse(data);
    console.log("✅ Itens normalizados (driver):", items.length);

    return res.json(items);
  } catch (e) {
    console.error("🔥 /api/report/driver/month error:", e);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Logout
app.post("/api/logout", async (req, res) => {
  try {
    await supabase.auth.signOut();
    req.session.destroy(() => {});
    res.json({ success: true, redirect: "/login.html" });
  } catch (error) {
    res.status(500).json({ error: "Logout failed" });
  }
});

// Pages
app.get("/", (req, res) => {
  if (req.session.user) {
    if (req.session.user.role === "driver") return res.redirect("/dashboard-driver");
    return res.redirect("/dashboard");
  }
  return res.redirect("/login-restaurant.html");
});

app.get("/login-driver", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard-driver");
  return res.redirect("/login-driver.html");
});

app.get("/login-restaurant", (req, res) => {
  if (req.session.user) return res.redirect("/dashboard");
  return res.redirect("/login-restaurant.html");
});

// dashboards
app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "dashboard.html"));
});
app.get("/dashboard.html", requireAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "dashboard.html"));
});

app.get("/dashboard-driver", requireAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "dashboard-driver.html"));
});
app.get("/dashboard-driver.html", requireAuth, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "dashboard-driver.html"));
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// ✅ HANDLER GLOBAL DE ERRO
app.use((err, req, res, next) => {
  console.error("🔥 ERRO GLOBAL NÃO CAPTURADO:", err);
  res.status(500).json({ error: "Unhandled server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;
