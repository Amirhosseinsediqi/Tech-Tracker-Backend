const express = require("express");
const router = express.Router();
const axios = require("axios");
const passport = require("passport");
const qs = require("qs");
const User = require("../../models/User");
const AuthTracker = require("../../models/AuthTracker");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { Meeting, getMeetingDetailsFromDB, refreshZoomToken, validateZoomToken } = require("../../index.js");


const redirecturl = `${process.env.BACKEND_URL}/auth/zoom/callback`;
const ZOOM_OAUTH_ENDPOINT = "https://zoom.us/oauth/token";
const ZOOM_OAUTH_ENDPOINT_USER = "https://zoom.us/oauth/authorize";

const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
};

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`,
      accessType: "offline",
      prompt: "consent",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log("Google OAuth callback received", { profile });
        
        // First try to find user by Google ID
        let user = await User.findByGoogleId(profile.id);
        
        if (!user) {
          // If not found by Google ID, try to find by email
          user = await User.findByEmail(profile.emails[0].value);
          
          if (user) {
            // Update existing user with Google credentials
            await user.updateGoogleAuth(profile, { accessToken, refreshToken });
          } else {
            // Create new user
            user = new User({ primaryEmail: profile.emails[0].value });
            await user.updateGoogleAuth(profile, { accessToken, refreshToken });
          }
        } else {
          // Update existing user's Google credentials
          await user.updateGoogleAuth(profile, { accessToken, refreshToken });
        }

        // Track the auth event
        await AuthTracker.create({
          userId: user._id,
          email: user.primaryEmail,
          eventType: 'google_auth',
          authProvider: 'google',
          success: true
        });
        
        return done(null, user);
      } catch (err) {
        console.error("Error in Google Strategy:", err);
        
        // Track the error
        if (user) {
          await AuthTracker.create({
            userId: user._id,
            email: user.primaryEmail,
            eventType: 'google_auth',
            authProvider: 'google',
            success: false,
            errorMessage: err.message
          });
        }
        
        return done(err, null);
      }
    }
  )
);

router.get("/check", async (req, res) => {
  try {
    console.log("Session Check:", {
      sessionID: req.sessionID,
      session: req.session,
      user: req.user,
      passport: req.session?.passport,
      cookies: req.cookies
    });

    // First try passport user
    let userId = req.user?._id;

    // If no passport user, try session
    if (!userId && req.session?.userId) {
      userId = req.session.userId;
    }
    
    if (!userId) {
      console.log("No userId found in session");
      return res.json({
        success: false,
        debug: "No authenticated user",
        sessionInfo: {
          hasSession: !!req.session,
          hasPassport: !!req.session?.passport,
          hasUser: !!req.user,
          sessionID: req.sessionID
        }
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      console.log("User not found in database for ID:", userId);
      return res.json({
        success: false,
        debug: "User not found in database",
        sessionInfo: {
          userId: userId,
          sessionID: req.sessionID
        }
      });
    }

    // Set session header for tracking
    res.set('x-session-id', req.sessionID);

    return res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        zoomEmail: user.zoomEmail,
        name: user.name
      },
      session: req.sessionID,
      debug: {
        sessionID: req.sessionID,
        hasPassport: !!req.session?.passport,
        hasSessionUser: !!req.session?.userId
      }
    });
  } catch (error) {
    console.error("Auth check error:", error);
    return res.status(500).json({ 
      error: error.message,
      session: req.sessionID
    });
  }
});


// Google OAuth routes
router.get(
  "/google",
  (req, res, next) => {
    console.log("Starting Google Auth Flow...");
    next();
  },
  passport.authenticate("google", {
    scope: ["profile", "email", "https://www.googleapis.com/auth/drive.file"],
    accessType: "offline",
    prompt: "consent",
  })
);

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/getstarted" }),
  async (req, res) => {
    try {
      console.log("Google OAuth callback received", {
        user: req.user,
        session: req.session,
        authInfo: req.authInfo
      });

      if (!req.user) {
        console.error("No user found in request");
        return res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=no_user`);
      }

      // Store the user ID in session
      req.session.userId = req.user._id;
      req.session.email = req.user.email;
      req.session.isAuthenticated = true;

      // Save session explicitly
      await new Promise((resolve, reject) => {
        req.session.save((err) => {
          if (err) {
            console.error("Error saving session:", err);
            reject(err);
          } else {
            console.log("Session saved successfully:", {
              sessionID: req.sessionID,
              session: req.session
            });
            resolve();
          }
        });
      });

      // Redirect to Zoom auth
      const clientId = process.env.ZOOM_CLIENT_ID;
      const zoomAuthUrl = `${ZOOM_OAUTH_ENDPOINT_USER}?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirecturl)}`;
      res.redirect(zoomAuthUrl);
    } catch (error) {
      console.error("Error in Google callback:", error);
      res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=google_auth_failed`);
    }
  }
);

// Zoom OAuth routes
router.get("/zoom", (req, res) => {
  const clientId = process.env.ZOOM_CLIENT_ID;
  const zoomAuthUrl = `${ZOOM_OAUTH_ENDPOINT_USER}?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirecturl)}`;
  res.redirect(zoomAuthUrl);
});

router.get("/zoom/callback", async (req, res) => {
  const code = req.query.code;
  console.log("Zoom callback received", {
    code,
    session: req.session,
    sessionID: req.sessionID
  });

  if (!code) {
    return res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=no_code`);
  }

  try {
    // Get user from session
    if (!req.session.passport?.user) {
      console.error("No user ID in session:", {
        sessionID: req.sessionID,
        session: req.session
      });
      return res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=no_session`);
    }

    const user = await User.findById(req.session.passport.user);
    if (!user) {
      console.error("User not found:", req.session.passport.user);
      return res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=user_not_found`);
    }

    // Get tokens from Zoom
    const tokenResponse = await axios.post(
      ZOOM_OAUTH_ENDPOINT,
      qs.stringify({
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirecturl,
      }),
      {
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${process.env.ZOOM_CLIENT_ID}:${process.env.ZOOM_CLIENT_SECRET}`
          ).toString("base64")}`,
        },
      }
    );

    // Get user profile with the access token
    const userResponse = await axios.get("https://api.zoom.us/v2/users/me", {
      headers: {
        Authorization: `Bearer ${tokenResponse.data.access_token}`,
      },
    });

    const zoomProfile = {
      id: userResponse.data.id,
      email: userResponse.data.email
    };

    console.log("Zoom user data:", zoomProfile);

    // Check if another user already has this Zoom ID
    const existingZoomUser = await User.findByZoomId(zoomProfile.id);
    if (existingZoomUser && existingZoomUser._id.toString() !== user._id.toString()) {
      console.log("Disconnecting Zoom from previous user:", existingZoomUser._id);
      
      // Track the change for the other user
      await AuthTracker.create({
        userId: existingZoomUser._id,
        email: existingZoomUser.primaryEmail,
        eventType: 'zoom_auth_removed',
        authProvider: 'zoom',
        success: true,
        message: 'Zoom credentials moved to another account'
      });
      
      // Remove Zoom credentials from the other user
      await existingZoomUser.disconnectZoom();
    }

    // Update Zoom information for current user
    await user.updateZoomAuth(zoomProfile, tokenResponse.data);

    // Track the auth event
    await AuthTracker.create({
      userId: user._id,
      email: user.primaryEmail,
      eventType: 'zoom_auth',
      authProvider: 'zoom',
      success: true
    });

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  } catch (error) {
    console.error("Error in Zoom callback:", error);
    
    // Track the error
    if (req.session.passport?.user) {
      const user = await User.findById(req.session.passport.user);
      if (user) {
        await AuthTracker.create({
          userId: user._id,
          email: user.primaryEmail,
          eventType: 'zoom_auth',
          authProvider: 'zoom',
          success: false,
          errorMessage: error.message
        });
      }
    }
    
    res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=zoom_auth_failed`);
  }
});

module.exports = router;
