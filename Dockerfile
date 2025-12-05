# ---------- BASE ----------
FROM node:20-alpine

# ---------- APP DIR ----------
WORKDIR /app

# ---------- DEPENDENCIES ----------
# copia só package* primeiro pra aproveitar cache
COPY package*.json ./

# instala só prod deps
RUN npm ci --omit=dev

# ---------- SOURCE ----------
COPY . .

# ---------- ENV / PORT ----------
ENV NODE_ENV=production
ENV PORT=3000

# ---------- EXPOSE (interna) ----------
EXPOSE 3000

# ---------- START ----------
# se teu start é "node server.js" beleza
# se for outro arquivo, ajusta aqui.
CMD ["node", "server.js"]
