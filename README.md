# Ares Backend

LinkedIn OAuth token exchange server for the Ares Android app.

## Deploy to Railway (free)

1. Install Railway CLI or use the web UI at railway.app
2. Create a new project and connect this folder
3. Set these environment variables in Railway dashboard:

```
LINKEDIN_CLIENT_ID=86pgp3ftk0xg3h
LINKEDIN_CLIENT_SECRET=your_new_secret_here
REDIRECT_URI=com.example.businesscardscanner://linkedin/callback
PORT=3000
```

4. Deploy — Railway gives you a URL like `https://ares-backend.up.railway.app`
5. Copy that URL into `LinkedInAuthManager.kt` → `BACKEND_URL`

## LinkedIn App Setup

In your LinkedIn Developer app settings:
- Add this to Authorized Redirect URLs:
  `com.example.businesscardscanner://linkedin/callback`
- Make sure "Sign In with LinkedIn using OpenID Connect" product is added

## Endpoints

- `GET /` — health check
- `POST /auth/linkedin/token` — exchange auth code for token + user profile
- `POST /auth/linkedin/verify` — verify an existing token
