const API_BASE_URL = process.env.CONTROL_PLANE_API_URL?.replace(/\/$/, "");

function unavailable() {
  return Response.json(
    { error: "Control-plane API is unavailable", storageReady: false },
    { status: 503 },
  );
}

async function forward(request: Request) {
  if (!API_BASE_URL) return unavailable();

  const incomingUrl = new URL(request.url);
  const targetUrl = `${API_BASE_URL}/api/audit-events${incomingUrl.search}`;

  try {
    const response = await fetch(targetUrl, {
      method: request.method,
      headers: request.headers.get("content-type")
        ? { "content-type": request.headers.get("content-type") as string }
        : undefined,
      body: request.method === "POST" ? await request.text() : undefined,
      cache: "no-store",
    });
    return new Response(response.body, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") ?? "application/json",
      },
    });
  } catch {
    return unavailable();
  }
}

export async function GET(request: Request) {
  return forward(request);
}

export async function POST(request: Request) {
  return forward(request);
}
