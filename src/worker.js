// Punto d'ingresso per Cloudflare Workers (vedi wrangler.toml).

import { createApp } from './app.js';

const handle = createApp();

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
