const express = require("express");
const router = express.Router();
const axios = require("axios");
const passport = require("passport");
const qs = require("qs");
const User = require("../../models/User");

const redirecturl = `${process.env.BACKEND_URL}/auth/zoom/callback`;
const ZOOM_OAUTH_ENDPOINT = "https://zoom.us/oauth/token";

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
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req, res) => {
    try {
      console.log("Google OAuth callback received");

      if (!req.user) {
        console.error("No user found in request");
        return res.redirect("/login");
      }

      const user = await User.findById(req.user._id);
      if (!user) {
        console.error("User not found in database");
        return res.redirect(`${process.env.FRONTEND_URL}/getstarted`);
      }

      if (req.authInfo?.accessToken) {
        user.accessToken = req.authInfo.accessToken;
      }
      if (req.authInfo?.refreshToken) {
        user.refreshToken = req.authInfo.refreshToken;
      }

      await user.save();
      req.session.email = user.email;
      res.redirect("/auth/zoom");
    } catch (error) {
      console.error("Error in Google callback:", error);
      res.redirect(`${process.env.FRONTEND_URL}/getstarted`);
    }
  }
);

// Zoom OAuth routes
router.get("/zoom", (req, res) => {
  const clientId = process.env.ZOOM_CLIENT_ID;
  const zoomAuthUrl = `https://zoom.us/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirecturl}`;
  res.redirect(zoomAuthUrl);
});

router.get("/zoom/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).send("Authorization code is required.");
  }

  try {
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

    const zoomUserEmail = userResponse.data.email;
    const zoomUserId = userResponse.data.id;

    console.log("Zoom user data:", { zoomUserEmail, zoomUserId });

    // Find or create user
    let user = await User.findOne({
      $or: [{ email: zoomUserEmail }, { zoomEmail: zoomUserEmail }],
    });

    if (!user) {
      user = new User({
        email: zoomUserEmail,
        zoomEmail: zoomUserEmail,
      });
    } else {
      // Update zoom email if it's different
      if (user.zoomEmail !== zoomUserEmail) {
        user.zoomEmail = zoomUserEmail;
      }
    }

    // Update Zoom information
    user.zoomUserId = zoomUserId;
    user.zoomAccessToken = tokenResponse.data.access_token;
    user.zoomRefreshToken = tokenResponse.data.refresh_token;
    user.zoomTokenExpiration = new Date(
      Date.now() + tokenResponse.data.expires_in * 1000
    );

    await user.save();
    console.log("User saved:", user);

    // Set session data
    req.session.userId = user._id;
    req.session.zoomEmail = zoomUserEmail;

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    console.log("Session saved:", req.session);

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  } catch (error) {
    console.error("Error in Zoom OAuth callback:", error);
    res.redirect(`${process.env.FRONTEND_URL}/login?error=zoom_auth_failed`);
  }
});

module.exports = router;
