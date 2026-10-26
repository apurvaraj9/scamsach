import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/site";

// Public pages may be indexed; personal pages (history, saved cases) never.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/history", "/case/"] },
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}
