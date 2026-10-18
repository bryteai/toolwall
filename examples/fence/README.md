# fence — toolwall v0.2 page

The page served at [`fence.bryteai.studio`](https://fence.bryteai.studio).

It shows three real outputs of toolwall v0.2.0 (`components/Examples.tsx`: exact input strings
and the detector's output, including one miss) and the held-out results from
`results/v0_2/summary.json` (`components/Results.tsx`).

Until October 2026 this page played a scripted side-by-side replay of five attacks. Its
detector lines were written by hand and did not match the shipped rules, so it was removed.

## Build (static export)

```bash
npm install
npm run build        # -> out/  (Cloudflare Pages or any static host)
```

Next.js 16 static export, React 19, Tailwind v4.
