# StackNord

Modern webhotel application built with Node.js + Express + SQLite.

## Requirements
- Node.js 20+
- npm

## Install
```bash
npm install
```

## Run locally
```bash
cp .env.example .env
npm start
```

Open http://localhost:3000

## Environment variables
- `PORT`: Server port, default `3000`
- `NODE_ENV`: `development` or `production`
- `SESSION_SECRET`: secret used for session cookies
- `STRIPE_SECRET_KEY`: Stripe secret key
- `STRIPE_PUBLISHABLE_KEY`: Stripe publishable key
- `STRIPE_WEBHOOK_SECRET`: Stripe signing secret for webhooks
- `PAYPAL_ME_LINK`: PayPal link used in checkout
- `VIPPS_NUMBER`: Vipps number used for manual payments
- `CRYPTO_WALLET`: crypto wallet address for manual payments

## aaPanel deployment
1. Upload the project to a folder such as `/www/wwwroot/stacknord`.
2. Create `.env` with your real values.
3. In aaPanel, create a `Node.js Project` pointing to that folder.
4. Set `Startup file` to `server.js`.
5. Run `npm install` in the project folder.
6. Start the app.
7. Point your domain to the app port and enable HTTPS.

## Notes
- This version implements the front-end and customer flow required for a hosting marketplace, but not server provisioning.
- Stripe checkout requires valid webhook setup for actual payment confirmation.
- PayPal, Vipps and crypto are handled as manual payment flows in this version.
