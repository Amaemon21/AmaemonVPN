# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AmaemonVPN — Node.js backend for a commercial VPN service based on AmneziaWG (hardened WireGuard). Handles user auth, device management, subscription billing via YooKassa, and real-time WireGuard peer management on a Linux server.

## Commands

```bash
# Install dependencies
cd server && npm install

# Run locally (requires Linux with AmneziaWG installed)
cd server && npm start
# or via PM2:
cd server && pm2 start ecosystem.config.js

# No test suite configured
```

## Architecture

Everything lives in `server/server.js` — a single-file Express app (~540 lines). There are no modules, routes files, or layers.

**Database:** SQLite via `better-sqlite3`, stored at `/var/www/amaemonvpn/server/vpn.db` on the production server. Two tables:
- `users` — auth, subscription expiry (Unix timestamp), referral tracking
- `devices` — WireGuard peer info, per-device config path, download token, paused state

**WireGuard management:** The server directly shells out to `sudo awg` and `sudo rm` and calls the script `/etc/amnezia/amneziawg/add_client.sh`. Per-client keys live at `/etc/amnezia/amneziawg/clients/{client_name}/`. On startup, `rebuildWgConfig()` rewrites `/etc/amnezia/amneziawg/awg0.conf` and syncs all active peers. Every 5 minutes, `checkExpired()` pauses devices of users with lapsed subscriptions.

**Two "protocols":** Both use the same AmneziaWG config file. `amnezia2` just rewrites the `Endpoint` to a relay (`185.171.82.68:51820`) when serving the download.

**Pricing:** `PRICES` maps device count → monthly base price (RUB). `PERIODS` maps months → discount. `calcPrice(deviceCount, months)` combines them. New users get a 3-hour free trial on registration.

**Referrals:** When a referred user makes their first payment, the referrer gets `REFERRAL_BONUS_DAYS` (7) days added. Tracked by `referral_rewarded` flag to prevent double bonuses.

**JWT:** `JWT_SECRET` is generated with `crypto.randomBytes` at startup — **all tokens are invalidated on every server restart**.

**Payments:** YooKassa webhook at `POST /api/payment/webhook`. On `payment.succeeded`, extends `subscription_ends`, unpauses devices if subscription was expired, and handles referral bonus. `user_id` and `months` are passed via payment `metadata`.

## Environment Variables

Create a `.env` in `server/` with:
```
YOOKASSA_SHOP_ID=...
YOOKASSA_SECRET_KEY=...
```

Note: `ecosystem.config.js` contains legacy env vars (`REALITY_PUBLIC_KEY`, `XRAY_CONFIG_PATH`, etc.) that are not used in the current server code.

## Deployment

The server runs on Linux at `/var/www/amaemonvpn/server/` via PM2. The Node process must have `sudo` access for `awg` commands and filesystem operations under `/etc/amnezia/`. Admin access is gated by hardcoded email `toitol@mail.ru` checked in `adminOnly` middleware.
