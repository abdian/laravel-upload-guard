# Laravel Safeguard Documentation

Minimal and clean documentation for Laravel Safeguard.

## Quick Start

```bash
# Install dependencies
npm install

# Start dev server
npm run docs:dev
```

Open `http://localhost:5173`

## Build

```bash
npm run docs:build
```

## Structure

```
docs/
├── .vitepress/
│   ├── config.mjs       # VitePress config
│   └── theme/
│       ├── index.js     # Theme entry
│       └── style.css    # Custom styles
├── guide/               # User guide
│   ├── index.md         # What is Safeguard?
│   ├── installation.md
│   ├── quick-start.md
│   ├── usage.md
│   ├── rules.md
│   └── config.md
├── api/                 # API reference
│   ├── index.md         # Rules API
│   └── config.md        # Config API
└── index.md             # Homepage
```

## Features

- Clean and minimal design
- Mobile responsive
- Fast search
- Dark mode
- Copy code buttons
- Laravel-themed colors

## Pages

### Guide
- What is Safeguard? → `/guide/`
- Installation → `/guide/installation`
- Quick Start → `/guide/quick-start`
- Basic Usage → `/guide/usage`
- Validation Rules → `/guide/rules`
- Configuration → `/guide/config`

### API Reference
- Rules API → `/api/`
- Configuration API → `/api/config`
