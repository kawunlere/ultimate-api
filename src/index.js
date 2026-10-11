export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token",
    };
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    try {
      const rk = "ratelimit:" + clientIP;
      const rd = await env.KEYS.get(rk);
      if (rd) {
        const c = parseInt(rd) || 0;
        if (c > 10) return j({ success: false, message: "Too many" }, 429, cors);
        await env.KEYS.put(rk, String(c + 1), { expirationTtl: 60 });
      } else {
        await env.KEYS.put(rk, "1", { expirationTtl: 60 });
      }
    } catch (e) {}
    if (path === "/api/generate-key" && request.method === "POST") {
      try {
        const b = await request.json();
        const d = b.deviceId;
        if (!d || typeof d !== "string" || d.length < 5) return j({ success: false, message: "Invalid device ID" }, 400, cors);
        const ex = await env.KEYS.get(d);
        if (ex) {
          const da = JSON.parse(ex);
          if (new Date(da.expires) > new Date()) return j({ success: true, key: da.key, expires: da.expires, alreadyExists: true }, 200, cors);
        }
        const days = b.type === "premium" ? 30 : 2;
        const key = gk();
        const exp = new Date(Date.now() + days * 86400000).toISOString();
        const kd = { key, deviceId: d, expires: exp, created: new Date().toISOString(), type: b.type || "free", ip: clientIP, source: "auto" };
        await env.KEYS.put(d, JSON.stringify(kd));
        return j({ success: true, key, expires: exp, type: b.type || "free" }, 200, cors);
      } catch (e) { return j({ success: false, message: "Error" }, 500, cors); }
    }
    if (path === "/api/verify-key" && request.method === "POST") {
      try {
        const b = await request.json();
        const d = b.deviceId;
        const k = b.key;
        if (!d || !k) return j({ valid: false, message: "Missing" }, 400, cors);
        const s = await env.KEYS.get(d);
        if (!s) return j({ valid: false, message: "No key" }, 200, cors);
        const da = JSON.parse(s);
        if (da.key !== k) return j({ valid: false, message: "Wrong key" }, 200, cors);
        if (new Date(da.expires) < new Date()) return j({ valid: false, message: "Expired" }, 200, cors);
        return j({ valid: true, expires: da.expires, type: da.type }, 200, cors);
      } catch (e) { return j({ valid: false, message: "Error" }, 500, cors); }
    }
    function isA(r) { return r.headers.get("X-Admin-Token") === env.ADMIN_TOKEN; }
    if (path === "/api/admin/list" && request.method === "GET") {
      if (!isA(request)) return j({ error: "No" }, 401, cors);
      try {
        const l = await env.KEYS.list();
        const ks = [];
        for await (const k of l.keys) {
          if (k.name.startsWith("ratelimit:")) continue;
          const v = await env.KEYS.get(k.name);
          if (v) try { ks.push({ deviceId: k.name, ...JSON.parse(v) }); } catch (e) {}
        }
        return j({ keys: ks }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }
    if (path === "/api/admin/generate-free" && request.method === "POST") {
      if (!isA(request)) return j({ error: "No" }, 401, cors);
      try {
        const b = await request.json();
        const d = b.deviceId;
        const days = parseInt(b.days) || 2;
        if (!d || d.length < 5) return j({ success: false, message: "Bad" }, 400, cors);
        const key = gk();
        const exp = new Date(Date.now() + days * 86400000).toISOString();
        await env.KEYS.put(d, JSON.stringify({ key, deviceId: d, expires: exp, created: new Date().toISOString(), type: "free", source: "admin" }));
        return j({ success: true, key, expires: exp, type: "free" }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }
    if (path === "/api/admin/generate-premium" && request.method === "POST") {
      if (!isA(request)) return j({ error: "No" }, 401, cors);
      try {
        const b = await request.json();
        const d = b.deviceId;
        const days = parseInt(b.days) || 30;
        if (!d || d.length < 5) return j({ success: false, message: "Bad" }, 400, cors);
        const key = gk();
        const exp = new Date(Date.now() + days * 86400000).toISOString();
        await env.KEYS.put(d, JSON.stringify({ key, deviceId: d, expires: exp, created: new Date().toISOString(), type: "premium", source: "admin" }));
        return j({ success: true, key, expires: exp, type: "premium" }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }
    if (path.startsWith("/api/admin/delete/") && request.method === "DELETE") {
      if (!isA(request)) return j({ error: "No" }, 401, cors);
      const d = decodeURIComponent(path.replace("/api/admin/delete/", ""));
      try { await env.KEYS.delete(d); return j({ success: true, deleted: d }, 200, cors); }
      catch (e) { return j({ error: e.message }, 500, cors); }
    }
    return j({ error: "Not found" }, 404, cors);
  }
};
function gk() {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const s = [];
  for (let i = 0; i < 4; i++) {
    let seg = "";
    for (let j = 0; j < 4; j++) seg += c.charAt(Math.floor(Math.random() * c.length));
    s.push(seg);
  }
  return s.join("-");
}
function j(d, s, h) {
  return new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", ...h } });
}
