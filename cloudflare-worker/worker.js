/**
 * V2Box subscription endpoint на Cloudflare Workers с токен-защитой.
 *
 * Маршруты (нужен верный ?token=...):
 *   GET /sub?token=SECRET   -> подписка в base64 (формат по умолчанию для V2Box)
 *   GET /raw?token=SECRET   -> тот же список в plain text (фолбэк)
 *   всё остальное / неверный токен / чужой User-Agent -> 404 (endpoint «не существует»)
 *
 * Секреты (задаются в Cloudflare, НЕ в коде и НЕ в публичном репозитории):
 *   TOKEN        — секретный токен доступа (обязателен)
 *   SUBSCRIPTION — список ссылок vless/vmess/ss, по одной на строку (обязателен).
 *                  Пустые строки и строки, начинающиеся с //, игнорируются —
 *                  как в build-sub.sh, можно вставлять содержимое configs.txt как есть.
 *
 * Опциональная переменная:
 *   ALLOWED_UA   — список подстрок User-Agent через запятую (например "v2box").
 *                  Если задана — пускаются только клиенты с подходящим UA.
 *                  Если не задана — фильтрации по UA нет.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. Токен. Неверный/отсутствующий -> 404 (не 401), чтобы сканеры не видели endpoint.
    const token = url.searchParams.get("token");
    if (!env.TOKEN || !token || !timingSafeEqual(token, env.TOKEN)) {
      return notFound();
    }

    // 2. Необязательный фильтр по User-Agent.
    if (env.ALLOWED_UA) {
      const ua = (request.headers.get("user-agent") || "").toLowerCase();
      const allowed = env.ALLOWED_UA.split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      if (!allowed.some((sub) => ua.includes(sub))) {
        return notFound();
      }
    }

    // 3. Собрать список ссылок (те же правила, что в build-sub.sh).
    const links = (env.SUBSCRIPTION || "")
      .split(/\r?\n/)
      .map((l) => l.replace(/\s+$/, ""))
      .filter((l) => l.length > 0 && !/^\s*\/\//.test(l));

    if (links.length === 0) {
      return notFound();
    }

    // Список строк, разделённых \n, с завершающим \n — байт-в-байт как sub.txt/raw.txt.
    const list = links.join("\n") + "\n";

    // 4. Роутинг: /raw -> plain, всё прочее -> base64.
    const path = url.pathname.replace(/\/+$/, "");
    if (path.endsWith("/raw")) {
      return textResponse(list);
    }
    return textResponse(base64Utf8(list));
  },
};

// UTF-8-safe base64 одной строкой (btoa не вставляет переносы).
function base64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Сравнение без ранней утечки по времени.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function textResponse(body) {
  return new Response(body, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "x-robots-tag": "noindex, nofollow",
    },
  });
}

function notFound() {
  return new Response("Not found\n", {
    status: 404,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
