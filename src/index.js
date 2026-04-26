const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
// fetch is built-in in Node.js 18+

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

// Privacy policy endpoint (required by LinkedIn)
app.get('/privacy', (req, res) => {
  res.send(`
    <html>
      <head><title>Privacy Policy - Ares Business Card Scanner</title></head>
      <body>
        <h1>Privacy Policy</h1>
        <p>This app only accesses your LinkedIn profile information to authenticate your identity.</p>
        <p>We do not store or share your personal information with third parties.</p>
        <p>Contact: support@ares-app.com</p>
      </body>
    </html>
  `);
});

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

// LinkedIn OAuth callback handler
app.get('/auth/callback', (req, res) => {
  try {
    const { code, state, error } = req.query;
    
    if (error) {
      // Redirect back to app with error
      return res.redirect(`com.example.businesscardscanner://linkedin/callback?error=${encodeURIComponent(error)}`);
    }
    
    if (!code || !state) {
      return res.redirect(`com.example.businesscardscanner://linkedin/callback?error=missing_parameters`);
    }
    
    // Redirect back to app with authorization code and state
    res.redirect(`com.example.businesscardscanner://linkedin/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`);
    
  } catch (error) {
    console.error('Error in OAuth callback:', error);
    res.redirect(`com.example.businesscardscanner://linkedin/callback?error=server_error`);
  }
});

// Store PKCE challenge for mobile app
app.post('/auth/store-challenge', (req, res) => {
  try {
    const { state, codeVerifier } = req.body;
    
    if (!state || !codeVerifier) {
      return res.status(400).json({ error: 'Missing state or codeVerifier' });
    }
    
    // Store the code verifier with state as key
    pkceStore.set(state, codeVerifier);
    
    // Clean up old entries
    if (pkceStore.size > 1000) {
      const entries = Array.from(pkceStore.entries());
      entries.slice(0, 500).forEach(([key]) => pkceStore.delete(key));
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error storing PKCE challenge:', error);
    res.status(500).json({ error: 'Failed to store PKCE challenge' });
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
    
    // Get user profile information using basic scopes
    const profileResponse = await fetch('https://api.linkedin.com/v2/people/~:(id,firstName,lastName,profilePicture(displayImage~:playableStreams))', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });
    
    const emailResponse = await fetch('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`
      }
    });
    
    if (!profileResponse.ok) {
      console.error('Failed to fetch user profile');
      return res.status(400).json({ error: 'Failed to fetch user profile' });
    }
    
    const profileData = await profileResponse.json();
    const emailData = emailResponse.ok ? await emailResponse.json() : null;
    
    // Extract user information
    const firstName = profileData.firstName?.localized?.en_US || '';
    const lastName = profileData.lastName?.localized?.en_US || '';
    const name = `${firstName} ${lastName}`.trim();
    const email = emailData?.elements?.[0]?.['handle~']?.emailAddress || '';
    const picture = profileData.profilePicture?.['displayImage~']?.elements?.[0]?.identifiers?.[0]?.identifier || '';
    
    res.json({
      access_token: tokenData.access_token,
      expires_in: tokenData.expires_in,
      user: {
        id: profileData.id,
        name: name,
        email: email,
        picture: picture
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
    const response = await fetch('https://api.linkedin.com/v2/people/~:(id,firstName,lastName)', {
      headers: {
        'Authorization': `Bearer ${access_token}`
      }
    });
    
    if (!response.ok) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    
    const userData = await response.json();
    const firstName = userData.firstName?.localized?.en_US || '';
    const lastName = userData.lastName?.localized?.en_US || '';
    const name = `${firstName} ${lastName}`.trim();
    
    res.json({ 
      valid: true, 
      user: {
        id: userData.id,
        name: name,
        email: '', // Email requires separate API call
        picture: ''
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