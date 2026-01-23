# Model Agency

Running (quick)

```bash
make deps
make css
make gen
air
```

Project summary

Small Go web app using Go templates for server-side rendering and Alpine.js for small UI interactivity.

Repository layout (short)

- `main.go`: server logic and route registration
- `src/pages/` and `src/components/`: page and component `.templ` files (templates)
- `public/`: public/static files served to clients

Alpine.js

Add Alpine to your base template (e.g., `root.templ`) via CDN for quick use:

```html
<script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
```

Common patterns: `x-data`, `x-show`, `@click`.

Templates & components

- Edit `.templ` files in `src/pages` and `src/components`.
- Components can be included via `{{ template "name" . }}` or rendered using generated Go helpers if present.

Static assets

- Edit source assets in `static/` and ensure built assets are placed into `public/` for the server to serve.

Database

- Initialization SQL is in `sql/` (e.g., `sql/init.sql`).

Notes

- Keep templates minimal and logic in Go handlers. If you want, I can further shorten or add a `make dev` target.

Generated on project workspace. File location: README.md
