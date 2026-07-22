declare module "cloudflare:workers" {
  export const env: {
    DB?: any;
  };
}

interface Fetcher {
  fetch(input: Request | string | URL, init?: RequestInit): Promise<Response>;
}

interface D1Database {
  prepare(query: string): unknown;
  batch(statements: unknown[]): Promise<unknown[]>;
}
