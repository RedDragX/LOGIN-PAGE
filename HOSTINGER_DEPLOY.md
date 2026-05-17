# 🚀 pgroom — Hostinger Deployment Guide

This guide walks you through uploading the **already-built** production package to **Hostinger shared hosting** (or any cPanel host) and getting it live in about 10 minutes.

---

## 📦 What you have

After running the build, two artefacts are produced:

| Path | What it is |
|------|------------|
| `/app/hostinger_deploy/` | Loose folder — upload contents to `public_html/` via File Manager |
| `/app/pgroom_hostinger.zip` (≈ 250 KB) | Single zip — easier to upload + extract on Hostinger |

Both contain **identical files**. Use whichever is easier.

### Contents (drop straight into `public_html/`)
```
public_html/
├── .htaccess               ← SPA routing, gzip, caching, security headers
├── config.js               ← Runtime API URL (EDIT AFTER UPLOAD)
├── index.html              ← Branded SEO meta, no telemetry
├── manifest.json           ← PWA manifest
├── asset-manifest.json     ← (CRA internal)
├── static/
│   ├── css/main.*.css      ← Minified + hashed (77 KB)
│   └── js/main.*.js        ← Minified + hashed (~ 240 KB gzipped)
└── api/
    ├── .htaccess           ← API folder routing
    └── index.php           ← Placeholder for future PHP backend
```

---

## 🛫 Deploy in 5 steps

### 1. Build the production package (once)
```bash
bash /app/scripts/build_hostinger.sh
```
You'll get `/app/pgroom_hostinger.zip`.

### 2. Download the zip to your computer
- In Emergent: open the file tree, right-click `pgroom_hostinger.zip` → **Download**, OR
- Use the integrated terminal to base64 it and copy from the preview

### 3. Upload to Hostinger
1. Login to **hPanel → Files → File Manager**
2. Open `public_html/` (or your subdomain folder)
3. **Empty the folder** if there's a default Hostinger placeholder page
4. Click **Upload Files** → select `pgroom_hostinger.zip`
5. Right-click the uploaded zip → **Extract** → extract to current folder
6. Delete the zip after extraction

### 4. Configure your backend URL ⚙️ **(IMPORTANT)**
Open `public_html/config.js` in File Manager → **Edit**.

Change this line to your actual backend URL:
```js
window.__APP_CONFIG__ = {
  API_URL: "https://your-backend-url.com/api",  ← edit this
  ...
};
```

**Common values:**

| Where your backend lives | Set API_URL to |
|--------------------------|----------------|
| Render / Railway / Fly | `https://pgroom-api.onrender.com/api` |
| AWS / DigitalOcean VPS | `https://api.pgroom.in/api` |
| Same Hostinger domain (PHP backend later) | `/api` |
| Keep using Emergent preview (testing only) | `https://b43ba1fb-17cf-4d2f-8231-74eec2294447.preview.emergentagent.com/api` |

Click **Save**. No rebuild needed — the next page load picks it up.

### 5. Connect your domain
- In hPanel → **Domains** → point `pgroom.in` (or your domain) to `public_html/`
- Enable SSL (Hostinger → Security → SSL → **Install SSL**)
- Visit `https://pgroom.in` — site is live 🎉

---

## 🧠 How it works

- **SPA routing** (e.g. `/properties`, `/dashboard`): `.htaccess` rewrites any non-file URL to `index.html` so React Router takes over
- **Runtime API config**: `config.js` is loaded **before** the React bundle, sets `window.__APP_CONFIG__`. Inside `api.js` we read this first; no rebuild needed to switch backends
- **Asset caching**: hashed bundles (`main.abc123.js`) are cached for 1 year; `index.html` and `config.js` are never cached (so updates appear immediately)
- **Compression**: Apache mod_deflate gzips HTML/CSS/JS on the fly → typical payload drops 60-80%
- **Security**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` headers all set

---

## 🩺 Troubleshooting

| Symptom | Fix |
|---------|-----|
| Site loads but pages show "Not Found" on refresh | `.htaccess` not picked up. Hostinger usually allows it by default; if not, contact support to enable `mod_rewrite` |
| API calls fail with CORS | Either set your backend's CORS to allow your Hostinger domain, OR run the backend on a subdomain (e.g. `api.pgroom.in`) and disable CORS entirely |
| Fonts look generic | Check console — `fonts.googleapis.com` must be reachable. If your country blocks it, host fonts locally |
| Old version keeps showing | Hard refresh (Ctrl+Shift+R). `index.html` is set to no-cache so this is rare |
| `config.js` changes don't apply | The file has `Cache-Control: no-store` set; if a CDN sits in front, purge its cache |
| 403 on direct file access | Hostinger's "directory listing" is disabled by our `.htaccess` (intentional). Direct URLs to files still work normally |

---

## 🔌 Backend deployment (for completeness)

The React frontend you uploaded is **stateless** — it needs a backend at `API_URL`. Your options:

### A. Hostinger Python hosting (newer plans)
Hostinger Business plan supports Python. Upload the FastAPI app there and point `API_URL` to it.

### B. Render.com (FREE, recommended)
1. Push `/app/backend` to GitHub
2. Render → **New Web Service** → connect repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. Add MongoDB via Render add-on or MongoDB Atlas free tier
6. Copy the Render URL → put in `config.js`

### C. Continue using Emergent backend
Just leave `API_URL` pointing to `https://...preview.emergentagent.com/api`. Works as-is, but slower from India.

### D. Port to PHP (your team's preference)
Keep the React frontend, rebuild the API in Laravel/Slim under `public_html/api/`. The `config.js` would then be set to `/api` (same-domain, no CORS).

---

## 🔄 To update the site later

1. Make changes locally → run `bash /app/scripts/build_hostinger.sh`
2. Upload the **new** `pgroom_hostinger.zip` to Hostinger
3. Extract & overwrite

`config.js` is **preserved by default** on extract-overwrite — your `API_URL` setting stays.

---

## 📊 Performance snapshot (after build)

| Metric | Value |
|--------|-------|
| Total uncompressed | 932 KB |
| Total gzipped | ≈ 250 KB |
| JS bundle (main) | 798 KB → 230 KB gzipped |
| CSS bundle | 77 KB → 14 KB gzipped |
| Lighthouse target | Performance ≥ 90 |
| Mobile responsive | ✅ Tailwind breakpoints, viewport-fit=cover |

---

Made for **Reliable Co. — pgroom®** 🏠
