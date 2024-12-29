require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");
const qs = require("qs");
const { debug } = require("node:console");
const axios = require("axios");
const passport = require("passport");
const moment = require("moment");
const RedisStore = require("connect-redis").default;
const redis = require("./configs/redis");

const handleMeetingParticipantsReport = require("./routes/api/handleMeetingParticipantsReport");
const { tokenCheck } = require("./middlewares/tokenCheck");
const { google } = require("googleapis");
const { type } = require("node:os");
const User = require("./models/User");
const { brotliCompress } = require("node:zlib");
const ZOOM_OAUTH_ENDPOINT = "https://zoom.us/oauth/token";
const ZOOM_OAUTH_ENDPOINT_USER = "https://zoom.us/oauth/authorize";
const redirecturl = `${process.env.BACKEND_URL}/auth/zoom/callback`;
const PORT = process.env.PORT || 5501;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const bcrypt = require("bcryptjs");
const { getAuthenticatedClient } = require("./auth/googleAuth");

const app = express();
const clients = new Set();

// Create HTTP server first
const server = app.listen(PORT, () =>
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

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// MongoDB connection configuration
const mongoOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  family: 4,
  keepAlive: true,
  keepAliveInitialDelay: 300000
};

mongoose.connect("mongodb://mongodb:27017/meetings", mongoOptions)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
  setTimeout(() => {
    mongoose.connect("mongodb://mongodb:27017/meetings", mongoOptions);
  }, 5000);
});

// Session configuration
app.use(
  session({
    store: MongoStore.create({
      mongoUrl: "mongodb://mongodb:27017/meetings",
      collectionName: "sessions",
      ttl: 60 * 60 * 24 * 14, // 14 days
      autoRemove: 'native',
      touchAfter: 24 * 3600, // 24 hours
      crypto: {
        secret: process.env.SESSION_SECRET
      }
    }),
    secret: process.env.SESSION_SECRET,
    name: "Teach-Track",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 14 // 14 days
    },
  })
);

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
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          user = new User({
            googleId: profile.id,
            email: profile.emails[0].value,
            name: profile.displayName,
          });
        }

        // Update tokens
        user.accessToken = accessToken;
        user.refreshToken = refreshToken;

        await user.save();

        return done(null, user, { accessToken, refreshToken });
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

app.use(passport.initialize());
app.use(passport.session());

connectWithRetry();

// redis.on("ready", () => console.log("Redis client ready!"));
// redis.on("error", (err) => console.error("Redis error:", err));

// setTimeout(() => connectWithRetry(1), 3000);

app.use(express.json());

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

app.post("/auth/logout", (req, res) => {
  try {
    if (!req.session) {
      return res.status(200).json({ message: "Already logged out" });
    }

    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
        return res.status(500).json({ error: "Failed to logout" });
      }
      ظ;

      // Clear the session cookie
      res.clearCookie("tech-trach", {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        path: "/",
      });

      res.status(200).json({ message: "Logged out successfully" });
    });
  } catch (error) {
    console.error("Error during logout:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.use(express.urlencoded({ extended: false }));

app.options("*", cors());

app.use("/auth", require("./routes/api/auth"));

const meetingSchema = new mongoose.Schema({
  id: {
    type: Number,
    required: true,
    unique: true,
  },
  name: {
    type: String,
    required: true,
  },
  delayPercentage: {
    type: Number,
    required: true,
    min: 0,
    max: 100,
  },
  allowTime: {
    type: Number,
    required: true,
    min: 0,
    max: 20,
  },
});

const userSchema = new mongoose.Schema({
  googleId: { type: String, required: false, unique: true },
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  accessToken: { type: String },
  refreshToken: { type: String },
  spreadsheetId: { type: String },
  zoomUserId: { type: String },
});

const Meeting =
  mongoose.models.Meeting || mongoose.model("Meeting", meetingSchema);

const getMeetingDetailsFromDB = async (id) => {
  try {
    console.log("Meeting ID to fetch: ", id);
    const meetingDetails = await Meeting.findOne({ id: Number(id) }).exec();
    console.log("from meetinghelper: ", meetingDetails);

    if (!meetingDetails) {
      throw new Error(`Meeting with ID ${id} not found`);
    }
    return meetingDetails;
  } catch (error) {
    console.error(`Error fetching meeting details: ${error.message}`);
    throw error;
  }
};

// redirecturl
const getToken = async (code, user) => {
  try {
    console.log("Exchanging authorization code for token");

    const tokenResponse = await axios.post(
      "https://zoom.us/oauth/token",
      null,
      {
        params: {
          grant_type: "authorization_code",
          code: code,
          redirect_uri: process.env.ZOOM_REDIRECT_URL,
        },
        headers: {
          Authorization: `Basic ${Buffer.from(
            `${process.env.ZOOM_CLIENT_ID}:${process.env.ZOOM_CLIENT_SECRET}`
          ).toString("base64")}`,
        },
      }
    );

    if (!tokenResponse.data.access_token) {
      throw new Error("No access token in response");
    }

    // Get user info
    const userResponse = await axios.get("https://api.zoom.us/v2/users/me", {
      headers: {
        Authorization: `Bearer ${tokenResponse.data.access_token}`,
      },
    });

    // Update user with Zoom info
    user.zoomUserId = userResponse.data.id;
    user.zoomAccessToken = tokenResponse.data.access_token;
    user.zoomRefreshToken = tokenResponse.data.refresh_token;
    user.zoomTokenExpiration = new Date(
      Date.now() + tokenResponse.data.expires_in * 1000
    );

    await user.save();
    console.log("Initial token exchange successful for user:", user._id);

    return tokenResponse.data.access_token;
  } catch (error) {
    console.error(
      "Error in token exchange:",
      error.response?.data || error.message
    );
    throw error;
  }
};

app.post("/", async (req, res) => {
  console.log("Hello My creator");
  res.send("Request received");
});

const refreshZoomToken = async (user) => {
  try {
    console.log("Attempting to refresh Zoom token for user:", user._id);

    if (!user.zoomRefreshToken) {
      throw new Error("No refresh token available");
    }

    const tokenResponse = await axios.post(
      "https://zoom.us/oauth/token",
      null,
      {
        params: {
          grant_type: "refresh_token",
          refresh_token: user.zoomRefreshToken,
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
    user.zoomAccessToken = tokenResponse.data.access_token;
    user.zoomRefreshToken = tokenResponse.data.refresh_token;
    user.zoomTokenExpiration = new Date(
      Date.now() + tokenResponse.data.expires_in * 1000
    );

    await user.save();
    console.log("Token refreshed successfully for user:", user._id);

    // Verify the token works by making a test API call
    try {
      await axios.get("https://api.zoom.us/v2/users/me", {
        headers: {
          Authorization: `Bearer ${user.zoomAccessToken}`,
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

    return user.zoomAccessToken;
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

    if (!user.zoomTokenExpiration || !user.zoomAccessToken) {
      console.log("No token or expiration found, refreshing token");
      return await refreshZoomToken(user);
    }

    const currentTime = Date.now();
    const tokenExpirationTime = new Date(user.zoomTokenExpiration).getTime();

    // Refresh if token is expired or will expire in the next 5 minutes
    if (currentTime >= tokenExpirationTime - 5 * 60 * 1000) {
      console.log("Token expired or expiring soon, refreshing");
      return await refreshZoomToken(user);
    }

    // Verify the current token works
    try {
      await axios.get("https://api.zoom.us/v2/users/me", {
        headers: {
          Authorization: `Bearer ${user.zoomAccessToken}`,
        },
      });
      console.log("Current token verified successfully");
    } catch (error) {
      console.log("Current token verification failed, refreshing");
      return await refreshZoomToken(user);
    }

    console.log("Token is valid and verified");
    return user.zoomAccessToken;
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
        const meetingDetails = {
          duration: req.body.payload.object.duration,
          startTime: req.body.payload.object.start_time,
          endTime: req.body.payload.object.end_time,
          topic: req.body.payload.object.topic,
        };

        console.log("Meeting ID:", meetingId);
        console.log("Meeting Details:", meetingDetails);

        // Check if meeting settings already exist
        let meetingSettings = await Meeting.findOne({ id: meetingId });

        // If no settings exist, create default settings
        if (!meetingSettings) {
          meetingSettings = new Meeting({
            id: meetingId,
            name: meetingId.toString(), // Use meeting ID as name
            delayPercentage: 80, // 80% default
            allowTime: 10, // 10 minutes default
          });

          await meetingSettings.save();
          console.log("Created default meeting settings:", meetingSettings);
        }

        const hostId = req.body.payload.object.host_id;
        console.log("Host ID:", hostId);

        // Find the user based on their Zoom host ID
        const user = await User.findOne({ zoomUserId: hostId });
        if (!user) {
          console.error("User not found for host ID:", hostId);
          return res.status(404).send("User not found");
        }

        // Validate and refresh token if needed
        const accessToken = await validateZoomToken(user);
        if (!accessToken) {
          console.error("Failed to get valid access token");
          return res.status(400).send("No valid access token available");
        }

        // Add access token to meeting details
        console.log("Using Zoom access token:", "***token-hidden***");
        meetingDetails.accessToken = accessToken;

        await handleMeetingParticipantsReport(
          meetingId,
          user._id,
          meetingDetails
        );
        res.status(200).send("Webhook received and processed");
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
          Authorization: `Bearer ${user.zoomAccessToken}`,
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

app.get("/api/auth/user/email", isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json({
      email: user.email,
      zoomEmail: user.zoomEmail,
    });
  } catch (error) {
    console.error("Error fetching user email:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/auth/status", async (req, res) => {
  try {
    const userId = req.session.userId;
    if (!userId) {
      return res.json({ authenticated: false });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
      },
    });
  } catch (error) {
    console.error("Error checking auth status:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
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

module.exports = { Meeting, getMeetingDetailsFromDB };
