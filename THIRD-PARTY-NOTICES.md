# Third-Party Notices

mtls-certificate-manager is licensed under the MIT License (see `LICENSE`).
It includes the following third-party software.

## Vendored code

### Lucide icons

- **Where**: `src/config/icons.js`
- **What**: SVG path data for a subset of icons, inlined as template strings
  so the app never fetches icons from a CDN (keeps a strict
  `script-src 'self'` CSP and works with no outbound network access).
- **License**: ISC (https://github.com/lucide-icons/lucide/blob/main/LICENSE)
- **Copyright**: Copyright (c) 2020, Lucide Contributors

## npm dependencies

| Package | Version | License |
|---|---|---|
| argon2 | 0.41.1 | MIT |
| connect-flash | 0.1.1 | MIT |
| ejs | 3.1.10 | Apache-2.0 |
| express | 4.22.2 | MIT |
| express-rate-limit | 7.5.1 | MIT |
| express-session | 1.19.0 | MIT |
| helmet | 8.3.0 | MIT |
| js-yaml | 4.3.1 | MIT |
| node-forge | 1.4.0 | (BSD-3-Clause OR GPL-2.0) — used here under BSD-3-Clause |

Full license text for each package is included with the package itself at
`node_modules/<package>/LICENSE` (or `license.md`) after `npm install`, and
in each package's public repository.

This list covers direct dependencies declared in `package.json`. Run
`npx license-checker --summary` for the full transitive dependency tree.
