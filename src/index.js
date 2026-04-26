const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// LinkedIn OAuth configuration
const LINKEDIN_CLIENT_ID = process.env.LINKEDIN_CLIENT_ID;
const LINKEDIN_CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const LINKEDIN_REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// In-memory storage for PKCE challenges (use Redis/database in production)
const pkceStore = new Map();

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ status: 'Ares backend running' });
});

// Generate PKCE challenge
app.post('/auth/pkce-challenge', (req, res) => {
  try {
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    
    const state = crypto.randomBytes(16).toString('hex');
    
    // Store the code verifier with state as key
    pkceStore.set(state, codeVerifier);
    
    // Clean up old entries (simple cleanup, use proper TTL in production)
    if (pkceStore.size > 1000) {
      const entries = Array.from(pkceStore.entries());
      entries.slice(0, 500).forEach(([key]) => pkceStore.delete(key));
    }
    
    res.json({
      codeChallenge,
      state
    });
  } catch (error) {
    console.error('Error generating PKCE challenge:', error);
    res.status(500).json({ error: 'Failed to generate PKCE challenge' });
  }
});

// Exchange authorization code for access token
app.post('/auth/token', async (req, res) => {
  try {
    const { code, state } = req.body;
    
    if (!code || !state) {
      return res.status(400).json({ error: 'Missing code or state parameter' });
    }
    
    // Retrieve and remove the code verifier
    const codeVerifier = pkceStore.get(state);
    if (!codeVerifier) {
      return res.status(400).json({ error: 'Invalid or expired state parameter' });
    }
    pkceStore.delete(state);
    
    // Exchange code for access token
    const tokenResponse = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: LINKEDIN_CLIENT_ID,
        client_secret: LINKEDIN_CLIENT_SECRET,
        redirect_uri: LINKEDIN_REDIRECT_URI,
        code_verifier: codeVerifier
      })
    });
    
    const tokenData = await tokenResponse.json();
    
    if (!tokenResponse.ok) {
      console.error('LinkedIn token exchange failed:', tokenData);
      return res.status(400).json({ 
        error: 'Token exchange failed', 
        details: tokenData 
      });
    }
    
    // Get user profile information
    const profileResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });
    
    if (!profileResponse.ok) {
      console.error('Failed to fetch user profile');
      return res.status(400).json({ error: 'Failed to fetch user profile' });
    }
    
    const profileData = await profileResponse.json();
    
    res.json({
      access_token: tokenData.access_token,
      expires_in: tokenData.expires_in,
      user: {
        id: profileData.sub,
        name: profileData.name,
        email: profileData.email,
        picture: profileData.picture
      }
    });
    
  } catch (error) {
    console.error('Error in token exchange:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Validate access token
app.post('/auth/validate', async (req, res) => {
  try {
    const { access_token } = req.body;
    
    if (!access_token) {
      return res.status(400).json({ error: 'Missing access token' });
    }
    
    // Validate token by making a request to LinkedIn API
    const response = await fetch('https://api.linkedin.com/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });
    
    if (!response.ok) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    const userData = await response.json();
    res.json({ 
      valid: true, 
      user: {
        id: userData.sub,
        name: userData.name,
        email: userData.email,
        picture: userData.picture
      }
    });
    
  } catch (error) {
    console.error('Error validating token:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
  console.log(`Ares backend server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});