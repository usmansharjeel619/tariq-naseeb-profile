import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

export default defineConfig({
  site: "https://tariq.yiwutariq.com",
  output: "static",
  integrations: [sitemap({ filter: (page) => !page.endsWith("/thank-you/") })],
  compressHTML: true,
});
