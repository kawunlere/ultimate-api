export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Token",
    };
    if (method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    const ADMIN_TOKEN = env.ADMIN_TOKEN || "kawunlere_admin_2024_secure";
    const OWNER_KEY = env.OWNER_KEY || "OWNER-MASTER-2024-LIFETIME-kawunlere";
    const PAYSTACK_SECRET = env.PAYSTACK_SECRET || "";
    const isAdmin = (r) => r.headers.get("X-Admin-Token") === ADMIN_TOKEN;

    // Rate limit
    try {
      const rk = "ratelimit:" + clientIP;
      const rd = await env.KEYS.get(rk);
      if (rd) {
        const c = parseInt(rd) || 0;
        if (c > 5) return j({ success: false, message: "Slow down" }, 429, cors);
        await env.KEYS.put(rk, String(c + 1), { expirationTtl: 60 });
      } else {
        await env.KEYS.put(rk, "1", { expirationTtl: 60 });
      }
    } catch (e) {}

    if (path === "/api/generate-key" && method === "POST") {
      try {
        const b = await request.json();
        const d = b.deviceId;
        if (!d || typeof d !== "string" || d.length < 5) return j({ success: false, message: "Invalid device ID" }, 400, cors);
        const ex = await env.KEYS.get(d);
        if (ex) {
          const da = JSON.parse(ex);
          if (new Date(da.expires) > new Date()) return j({ success: true, key: da.key, expires: da.expires, alreadyExists: true, type: da.type }, 200, cors);
        }
        const key = gk();
        const exp = new Date(Date.now() + 2 * 86400000).toISOString();
        await env.KEYS.put(d, JSON.stringify({ key, deviceId: d, expires: exp, type: "free", days: 2, created: new Date().toISOString(), source: "free-ads" }));
        return j({ success: true, key, expires: exp, type: "free" }, 200, cors);
      } catch (e) { return j({ success: false, message: "Error" }, 500, cors); }
    }

    if (path === "/api/verify-key" && method === "POST") {
      try {
        const b = await request.json();
        const d = b.deviceId, k = b.key;
        if (!d || !k) return j({ valid: false, message: "Missing" }, 400, cors);
        const s = await env.KEYS.get(d);
        if (!s) return j({ valid: false, message: "No key" }, 200, cors);
        const da = JSON.parse(s);
        if (da.key !== k) return j({ valid: false, message: "Wrong key" }, 200, cors);
        if (new Date(da.expires) < new Date()) return j({ valid: false, message: "Expired" }, 200, cors);
        return j({ valid: true, expires: da.expires, type: da.type, daysLeft: Math.floor((new Date(da.expires) - new Date()) / 86400000) }, 200, cors);
      } catch (e) { return j({ valid: false, message: "Error" }, 500, cors); }
    }

    // Paystack Webhook - verify payment with Paystack, then create key
    if (path === "/api/paystack-webhook" && method === "POST") {
      try {
        const event = await request.json();
        if (event.event !== "charge.success") return j({ received: true }, 200, cors);
        const ref = event.data?.reference;
        const deviceId = event.data?.metadata?.deviceId;
        const days = parseInt(event.data?.metadata?.days) || 30;
        if (!ref || !deviceId) return j({ error: "Missing data" }, 400, cors);
        if (!PAYSTACK_SECRET) return j({ error: "Server not configured" }, 500, cors);
        // Verify with Paystack
        const verifyRes = await fetch("https://api.paystack.co/transaction/verify/" + encodeURIComponent(ref), {
          headers: { "Authorization": "Bearer " + PAYSTACK_SECRET }
        });
        const verifyData = await verifyRes.json();
        if (!verifyData.status || verifyData.data?.status !== "success") {
          return j({ error: "Payment not verified" }, 400, cors);
        }
        const key = gk();
        const exp = new Date(Date.now() + days * 86400000).toISOString();
        await env.KEYS.put(deviceId, JSON.stringify({
          key, deviceId, expires: exp, type: "premium", days,
          created: new Date().toISOString(),
          paymentRef: ref, amount: verifyData.data.amount / 100,
          email: verifyData.data.customer?.email,
          source: "paystack"
        }));
        return j({ success: true, key, expires: exp }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }

    if (path === "/api/owner-check" && method === "POST") {
      try {
        const b = await request.json();
        const d = b.deviceId, k = b.key;
        if (k === OWNER_KEY) {
          const exp = new Date(Date.now() + 365 * 50 * 86400000).toISOString();
          await env.KEYS.put(d, JSON.stringify({ key: OWNER_KEY, deviceId: d, expires: exp, type: "owner", days: 18250, created: new Date().toISOString(), source: "owner" }));
          return j({ valid: true, type: "owner", expires: exp }, 200, cors);
        }
        return j({ valid: false }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }

    if (path === "/api/admin/list" && method === "GET") {
      if (!isAdmin(request)) return j({ error: "No" }, 401, cors);
      try {
        const l = await env.KEYS.list();
        const ks = [];
        for await (const k of l.keys) {
          if (k.name.startsWith("ratelimit:")) continue;
          const v = await env.KEYS.get(k.name);
          if (v) try { ks.push({ deviceId: k.name, ...JSON.parse(v) }); } catch (e) {}
        }
        return j({ count: ks.length, keys: ks }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }
    if (path === "/api/admin/generate-free" && method === "POST") {
      if (!isAdmin(request)) return j({ error: "No" }, 401, cors);
      try {
        const b = await request.json();
        const d = b.deviceId, days = parseInt(b.days) || 2;
        if (!d || d.length < 5) return j({ success: false, message: "Bad" }, 400, cors);
        const key = gk();
        const exp = new Date(Date.now() + days * 86400000).toISOString();
        await env.KEYS.put(d, JSON.stringify({ key, deviceId: d, expires: exp, type: "free", days, created: new Date().toISOString(), source: "admin" }));
        return j({ success: true, key, expires: exp, type: "free" }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }
    if (path === "/api/admin/generate-premium" && method === "POST") {
      if (!isAdmin(request)) return j({ error: "No" }, 401, cors);
      try {
        const b = await request.json();
        const d = b.deviceId, days = parseInt(b.days) || 30;
        if (!d || d.length < 5) return j({ success: false, message: "Bad" }, 400, cors);
        const key = gk();
        const exp = new Date(Date.now() + days * 86400000).toISOString();
        await env.KEYS.put(d, JSON.stringify({ key, deviceId: d, expires: exp, type: "premium", days, created: new Date().toISOString(), source: "admin" }));
        return j({ success: true, key, expires: exp, type: "premium" }, 200, cors);
      } catch (e) { return j({ error: e.message }, 500, cors); }
    }
    if (path.startsWith("/api/admin/delete/") && method === "DELETE") {
      if (!isAdmin(request)) return j({ error: "No" }, 401, cors);
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
