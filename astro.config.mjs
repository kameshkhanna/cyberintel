
import { defineConfig } from 'astro/config';
import fs from 'node:fs';

const isDev = process.env.NODE_ENV !== 'production';

export default defineConfig({
  output: 'static',
  site: process.env.SITE_URL || 'https://example.pages.dev',

  vite: {
    server: isDev
      ? {
          https: {
            key: fs.readFileSync('./certs/localhost-key.pem'),
            cert: fs.readFileSync('./certs/localhost.pem'),
          },
        }
      : {},
  },
});


