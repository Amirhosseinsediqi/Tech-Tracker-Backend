require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const passport = require("passport");
const axios = require("axios");
const cors = require("cors");
const User = require("./models/User");
const handleMeetingParticipantsReport = require("./routes/api/handleMeetingParticipantsReport");
const { Meeting, getMeetingDetailsFromDB } = require("./utils/meetingHelper");
const qs = require("qs");
const { debug } = require("node:console");
const moment = require("moment");
const RedisStore = require("connect-redis").default;
const redis = require("./configs/redis");
const { google } = require("googleapis");
const { type } = require("node:os");
const AuthTracker = require('./models/AuthTracker');
const { brotliCompress } = require("node:zlib");
const ZOOM_OAUTH_ENDPOINT = "https://zoom.us/oauth/token";
const ZOOM_OAUTH_ENDPOINT_USER = "https://zoom.us/oauth/authorize";
const redirecturl = `${process.env.BACKEND_URL}/auth/zoom/callback`;
const PORT = process.env.PORT || 5501;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const { getAuthenticatedClient } = require("./auth/googleAuth");

const app = express();

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['x-session-id']
}));

app.set('trust proxy', 1);

// Session configuration
app.use(
  session({
    name: "session",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 24 * 60 * 60, // 1 day
      autoRemove: 'native',
      touchAfter: 24 * 3600 // Only update session once per day unless data changes
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
  })
);

// Initialize Passport and restore authentication state from session
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  console.log("Serializing user:", user._id);
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  console.log("Deserializing user ID:", id);
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    console.error("Error deserializing user:", err);
    done(err, null);
  }
});

// Debug middleware - log all requests
app.use((req, res, next) => {
  // console.log('Request Debug:', {
  //   url: req.url,
  //   method: req.method,
  //   headers: req.headers,
  //   cookies: req.cookies,
  //   sessionID: req.sessionID,
  //   session: req.session,
  //   user: req.user
  // });
  next();
});

// Basic routes
app.get("/", (req, res) => {
  res.json({
    status: "success",
    message: "Tech Track API is running",
    version: "1.0.0",
    endpoints: [
      "/auth/google",
      "/auth/zoom",
      "/meetings",
      "/webhook"
    ]
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "healthy" });
});

// Create HTTP server first
const server = app.listen(PORT, '0.0.0.0', () =>
  console.log(`Listening on port ${PORT}!`)
);

// Store connected clients
const connectWithRetry = async (attempt = 1) => {
  try {
    console.log(`Attempting Redis connection (Attempt ${attempt})`);

    if (redis.isReady) {
      console.log("Redis is already connected.");
      return;
    }

    await redis.connect();
    console.log("Connected to Redis successfully!");
  } catch (err) {
    console.error(
      `Attempt ${attempt}: Could not establish connection with Redis:`,
      err
    );
    const retryDelay = Math.min(attempt * 3000, 30000);
    console.log(`Retrying in ${retryDelay}ms`);

    setTimeout(() => {
      connectWithRetry(attempt + 1);
    }, retryDelay);
  }
};

// MongoDB connection configuration
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
  heartbeatFrequencyMS: 10000
};

// Connect to MongoDB with retry mechanism
const connectToMongoDB = async (retryCount = 0, maxRetries = 5) => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, mongoOptions);
    console.log('Connected to MongoDB successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    if (retryCount < maxRetries) {
      const delay = Math.min((retryCount + 1) * 5000, 30000);
      console.log(`Retrying connection in ${delay/1000} seconds... (Attempt ${retryCount + 1}/${maxRetries})`);
      setTimeout(() => connectToMongoDB(retryCount + 1, maxRetries), delay);
    }
  }
};

// Handle MongoDB connection events
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
  connectToMongoDB();
});

mongoose.connection.on('connected', () => {
  console.log('MongoDB connected');
});

// Initial connection
connectToMongoDB();

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
        
        // First try to find user by googleId
        let user = await User.findOne({ googleId: profile.id });
        
        if (!user) {
          // If not found by googleId, try to find by email
          user = await User.findOne({ email: profile.emails[0].value });
          
          if (user) {
            // Update existing user with Google credentials
            user.googleId = profile.id;
            user.accessToken = accessToken;
            user.refreshToken = refreshToken;
          } else {
            // Create new user
            user = new User({
              googleId: profile.id,
              email: profile.emails[0].value,
              name: profile.displayName,
              accessToken,
              refreshToken
            });
          }
          await user.save();
        }
        
        return done(null, user);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

connectWithRetry();

// redis.on("ready", () => console.log("Redis client ready!"));
// redis.on("error", (err) => console.error("Redis error:", err));

// setTimeout(() => connectWithRetry(1), 3000);

const isAuthenticated = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
};

app.use((req, res, next) => {
  // console.log("Session data before serialization:", req.session);
  next();
});

app.post("/auth/logout", async (req, res) => {
  try {
    console.log('Logout request received:', {
      session: req.session,
      sessionID: req.sessionID,
      user: req.user
    });

    if (!req.session) {
      return res.status(200).json({ message: "Already logged out" });
    }

    // Store user info before destroying session
    const userId = req.session.userId;
    const user = await User.findById(userId);
    
    if (user) {
      // Track the logout event
      await AuthTracker.create({
        userId: user._id,
        email: user.email,
        eventType: 'logout',
        authProvider: user.googleId ? 'google' : (user.zoomUserId ? 'zoom' : 'email'),
        previousState: {
          googleId: user.googleId,
          zoomUserId: user.zoomUserId,
          accessToken: user.accessToken,
          refreshToken: user.refreshToken,
          spreadsheetId: user.spreadsheetId
        },
        success: true
      });
    }

    // Destroy the session
    await new Promise((resolve, reject) => {
      req.session.destroy((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Clear the session cookie
    res.clearCookie("session", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      domain: '.rubikamp.org',
      path: "/"
    });

    // Update user's last logout time
    if (user) {
      await User.findByIdAndUpdate(user._id, {
        lastLogout: new Date()
      }).catch(err => {
        console.error('Error updating user logout time:', err);
        // Track the error
        AuthTracker.create({
          userId: user._id,
          email: user.email,
          eventType: 'logout',
          authProvider: user.googleId ? 'google' : (user.zoomUserId ? 'zoom' : 'email'),
          success: false,
          errorMessage: err.message
        }).catch(e => console.error('Error creating auth tracker:', e));
      });
    }

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Error during logout:", error);
    
    // Track the error if we have user information
    if (req.user) {
      AuthTracker.create({
        userId: req.user._id,
        email: req.user.email,
        eventType: 'logout',
        authProvider: req.user.googleId ? 'google' : (req.user.zoomUserId ? 'zoom' : 'email'),
        success: false,
        errorMessage: error.message
      }).catch(e => console.error('Error creating auth tracker:', e));
    }
    
    res.status(500).json({ error: "Internal server error" });
  }
}); 

app.use(express.urlencoded({ extended: false }));

app.options("*", cors());

app.use("/auth", require("./routes/api/auth"));

app.post("/", async (req, res) => {
  console.log("Hello My creator");
  res.send("Request received");
});

const refreshZoomToken = async (user) => {
  try {
    console.log("Attempting to refresh Zoom token for user:", user._id);

    if (!user.zoom?.refreshToken) {
      throw new Error("No refresh token available");
    }

    const tokenResponse = await axios.post(
      "https://zoom.us/oauth/token",
      null,
      {
        params: {
          grant_type: "refresh_token",
          refresh_token: user.zoom.refreshToken,
        },
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${process.env.ZOOM_CLIENT_ID}:${process.env.ZOOM_CLIENT_SECRET}`
          ).toString("base64")}`,
        },
      }
    );

    if (!tokenResponse.data.access_token) {
      throw new Error("No access token in refresh response");
    }

    // save tokens in db
    user.zoom.accessToken = tokenResponse.data.access_token;
    user.zoom.refreshToken = tokenResponse.data.refresh_token;
    user.zoom.tokenExpiration = new Date(
      Date.now() + tokenResponse.data.expires_in * 1000
    );

    await user.save();
    console.log("Token refreshed successfully for user:", user._id);

    // Verify the token works by making a test API call
    try {
      await axios.get("https://api.zoom.us/v2/users/me", {
        headers: {
          Authorization: `Bearer ${user.zoom.accessToken}`,
        },
      });
      console.log("Token verified successfully");
    } catch (verifyError) {
      console.error(
        "Token verification failed:",
        verifyError.response?.data || verifyError.message
      );
      throw new Error("Token verification failed");
    }

    return user.zoom.accessToken;
  } catch (error) {
    console.error(
      "Error refreshing Zoom token:",
      error.response?.data || error.message
    );
    throw error;
  }
};

const validateZoomToken = async (user) => {
  try {
    console.log("Validating Zoom token for user:", user._id);

    if (!user.zoom.tokenExpiration || !user.zoom.accessToken) {
      console.log("No token or expiration found, refreshing token");
      return await refreshZoomToken(user);
    }

    const currentTime = Date.now();
    const tokenExpirationTime = new Date(user.zoom.tokenExpiration).getTime();

    // Refresh if token is expired or will expire in the next 5 minutes
    if (currentTime >= tokenExpirationTime - 5 * 60 * 1000) {
      console.log("Token expired or expiring soon, refreshing");
      return await refreshZoomToken(user);
    }

    // Verify the current token works
    try {
      await axios.get("https://api.zoom.us/v2/users/me", {
        headers: {
          Authorization: `Bearer ${user.zoom.accessToken}`,
        },
      });
      console.log("Current token verified successfully");
    } catch (error) {
      console.log("Current token verification failed, refreshing");
      return await refreshZoomToken(user);
    }

    console.log("Token is valid and verified");
    return user.zoom.accessToken;
  } catch (error) {
    console.error("Error validating token:", error);
    throw error;
  }
};

app.post("/webhook", async (req, res) => {
  console.log("Webhook headers:", req.headers);
  console.log("Webhook body:", req.body);

  const message = `v0:${req.headers["x-zm-request-timestamp"]}:${JSON.stringify(
    req.body
  )}`;
  const hashForVerify = crypto
    .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
    .update(message)
    .digest("hex");
  const signature = `v0=${hashForVerify}`;

  if (req.headers["x-zm-signature"] === signature) {
    try {
      if (req.body.event === "endpoint.url_validation") {
        const hashForValidate = crypto
          .createHmac("sha256", process.env.ZOOM_WEBHOOK_SECRET_TOKEN)
          .update(req.body.payload.plainToken)
          .digest("hex");

        res.status(200).json({
          plainToken: req.body.payload.plainToken,
          encryptedToken: hashForValidate,
        });
      } else if (req.body.event === "meeting.ended") {
        const meetingId = req.body.payload.object.id;
        const accountId = req.body.payload.account_id;
        const hostId = req.body.payload.object.host_id;
        const meetingDetails = {
          duration: req.body.payload.object.duration,
          startTime: req.body.payload.object.start_time,
          endTime: req.body.payload.object.end_time,
          topic: req.body.payload.object.topic,
          accountId: accountId,
          hostId: hostId
        };

        console.log("Meeting ID:", meetingId);
        console.log("Meeting Details:", meetingDetails);
        console.log("Host ID:", hostId);

        // Check if meeting settings already exist
        let meetingSettings = await Meeting.findOne({ id: meetingId });

        // If no settings exist, create default settings
        if (!meetingSettings) {
          meetingSettings = new Meeting({
            id: meetingId,
            name: meetingDetails.topic || meetingId.toString(),
            delayPercentage: 80,
            allowTime: 10,
          });

          await meetingSettings.save();
          console.log("Created default meeting settings:", meetingSettings);
        }

        // First try to find the host user
        let user = await User.findOne({
          'zoom.id': hostId,
          'zoom.accessToken': { $exists: true }
        });

        // If host not found or no token, try to find any user with valid zoom token
        if (!user) {
          console.log("Host user not found, looking for any user with valid Zoom token");
          user = await User.findOne({
            'zoom.accessToken': { $exists: true }
          });
        }

        if (!user) {
          console.error("No user found with valid Zoom token");
          return res.status(404).send("No user found with valid Zoom token");
        }

        console.log("Found user for API access:", user.zoom.email);

        try {
          // Validate and refresh token if needed
          const accessToken = await validateZoomToken(user);
          if (!accessToken) {
            console.error("Failed to get valid access token");
            return res.status(400).send("No valid access token available");
          }

          // Add access token and account details to meeting details
          console.log("Using Zoom token from user:", user.zoom.email);
          meetingDetails.accessToken = accessToken;

          await handleMeetingParticipantsReport(
            meetingId,
            user._id,
            meetingDetails
          );
          res.status(200).send("Webhook received and processed");
        } catch (error) {
          console.error("Error processing meeting:", error);
          
          // If token validation fails, try to find another user with valid token
          const backupUser = await User.findOne({
            'zoom.accessToken': { $exists: true },
            _id: { $ne: user._id }  // Exclude the current user
          });

          if (backupUser) {
            console.log("Retrying with backup user:", backupUser.zoom.email);
            const backupToken = await validateZoomToken(backupUser);
            if (backupToken) {
              meetingDetails.accessToken = backupToken;
              await handleMeetingParticipantsReport(
                meetingId,
                backupUser._id,
                meetingDetails
              );
              return res.status(200).send("Webhook processed with backup user");
            }
          }
          
          // If all attempts fail, return error
          if (!res.headersSent) {
            res.status(500).send("Failed to process meeting");
          }
        }
      }
    } catch (error) {
      console.error("Error in webhook handling:", error);
      if (!res.headersSent) {
        res.status(500).send("Server Error");
      }
    }
  } else {
    res
      .status(401)
      .json({ message: "Unauthorized request to Zoom Webhook sample." });
  }
});

app.post("/meetings", async (req, res) => {
  console.log("Full request body:", req.body);

  const { id, name, delayPercentage, allowTime } = req.body;

  // Detailed logging
  console.log("Received meeting data:", {
    id: id,
    name: name,
    delayPercentage: delayPercentage,
    allowTime: allowTime,
  });

  try {
    const existingMeeting = await Meeting.findOne({ id: id });

    if (existingMeeting) {
      return res.status(400).json({ message: "Meeting ID already exist." });
    }

    const newMeeting = new Meeting({
      id,
      name,
      delayPercentage,
      allowTime,
    });
    await newMeeting.save();

    console.log("New meeting saved:", newMeeting);
    res.status(201).send("Meeting data saved successfully");
  } catch (err) {
    res.status(500).send("Failed to save data");
  }
});

app.post("/auth/signup", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists." });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      accessToken: null,
      refreshToken: null,
      zoomAccessToken: null,
      zoomRefreshToken: null,
      zoomTokenExpiration: null,
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("Error during signup:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/meetings/:id", async (req, res) => {
  try {
    const meetingId = req.params.id;
    const deletedMeeting = await Meeting.findOneAndDelete({ id: meetingId });

    if (deletedMeeting) {
      res.status(200).json({ message: "Meeting deleted successfully." });
    } else {
      res.status(404).json({ message: "Meeting not found." });
    }

    if (!deletedMeeting) {
      return res.status(404).json({ message: "Meeting not found." });
    }
  } catch (err) {
    res.status(500).json({ message: "Failed to delete meeting." });
  }
});

app.delete("/users/:id", async (req, res) => {
  try {
    const userId = req.params.id;
    const deletedUser = await User.findByIdAndDelete(userId);

    if (deletedUser) {
      // Delete session user
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
        }
        res.status(200).json({ message: "User deleted and session cleared." });
      });
    } else {
      res.status(404).json({ message: "User not found." });
    }
  } catch (err) {
    res.status(500).json({ message: "Failed to delete user." });
  }
});

app.get("/getmeetings", async (req, res) => {
  try {
    const meetings = await Meeting.find({});
    res.status(200).json(meetings);
  } catch (err) {
    console.error("Error fetching meetings:", err);
    res.status(500).json({ message: "Error fetching meetings." });
  }
});

app.get("/api/zoom/meetings", async (req, res) => {
  try {
    const userId = req.session.userId;

    if (!userId) {
      return res.status(401).send("User not authenticated. Please log in.");
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).send("User not found.");
    }

    if (
      !user.zoomTokenExpiration ||
      new Date(user.zoomTokenExpiration).getTime() < Date.now()
    ) {
      console.log("Refreshing Zoom access token...");
      await refreshZoomToken(user);
    }

    const response = await axios.get(
      "https://api.zoom.us/v2/users/me/meetings",
      {
        headers: {
          Authorization: `Bearer ${user.zoom.accessToken}`,
        },
      }
    );

    console.log("Meetings fetched successfully:", response.data);
    res.status(200).json(response.data);
  } catch (err) {
    console.error(
      "Error fetching Zoom meetings:",
      err.response?.data || err.message
    );
    res.status(500).send("Error fetching meetings.");
  }
});

// Google OAuth routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: [
      "profile",
      "email",
      "https://www.googleapis.com/auth/spreadsheets",
    ],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/getstarted" }),
  async (req, res) => {
    try {
      // Store the user ID in session
      req.session.userId = req.user._id;
      
      // Check if user already has Zoom credentials
      if (req.user.zoomUserId && req.user.zoomAccessToken) {
        // If user already has Zoom auth, redirect to dashboard
        res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
      } else {
        // If no Zoom auth, redirect to Zoom OAuth
        const zoomAuthUrl = `${ZOOM_OAUTH_ENDPOINT_USER}?response_type=code&client_id=${
          process.env.ZOOM_CLIENT_ID
        }&redirect_uri=${encodeURIComponent(redirecturl)}`;
        res.redirect(zoomAuthUrl);
      }
    } catch (error) {
      console.error("Error in Google auth callback:", error);
      res.redirect(`${process.env.FRONTEND_URL}/getstarted?error=auth_failed`);
    }
  }
);


app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    status: 'error',
    message: 'Something went wrong!'
  });
});

const cleanup = async () => {
  debug("\nClosing HTTP server");
  await redis.quit();
  server.close(() => {
    debug("\nHTTP server closed");
    process.exit();
  });
};

process.on("SIGTERM", cleanup);
process.on("SIGINT", cleanup);

module.exports = { refreshZoomToken, validateZoomToken };
