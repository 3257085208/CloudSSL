export const onRequest = async (context: any) => {
  const res = await context.next();
  const headers = new Headers(res.headers);
  headers.set('X-Powered-By', 'Cloudflare Pages Functions');
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type');
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers
  });
};
