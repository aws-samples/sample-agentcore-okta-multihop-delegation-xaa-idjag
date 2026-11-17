# Third-party files in web/vendor

The console loads these two files locally instead of from a CDN. They are unmodified copies of the published releases.

| File | Project | Version | Source | SHA-256 | License |
|---|---|---|---|---|---|
| `tailwind.min.js` | [Tailwind CSS](https://tailwindcss.com) (Play CDN build) | 3.4.17 | https://cdn.tailwindcss.com/3.4.17 | `176e894661aa9cdc9a5cba6c720044cbbf7b8bd80d1c9a142a7c24b1b6c50d15` | MIT, [LICENSE-tailwindcss.txt](LICENSE-tailwindcss.txt) |
| `lucide.min.js` | [Lucide](https://lucide.dev) icons | 1.26.0 | https://unpkg.com/lucide@1.26.0/dist/umd/lucide.min.js | `03eb9f60319017f2510aa01731c24cad33d056e67140656d0fe135ec436597a1` | ISC, [LICENSE-lucide.txt](LICENSE-lucide.txt) |

To check a copy: `shasum -a 256 web/vendor/*.js`, then compare with the table.
