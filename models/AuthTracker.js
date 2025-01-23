const mongoose = require('mongoose');

const authTrackerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  email: {
    type: String,
    required: true
  },
  eventType: {
    type: String,
    enum: ['google_auth', 'zoom_auth', 'email_auth', 'logout'],
    required: true
  },
  authProvider: {
    type: String,
    enum: ['google', 'zoom', 'email'],
    required: true
  },
  previousState: {
    googleId: String,
    zoomUserId: String,
    accessToken: String,
    refreshToken: String,
    spreadsheetId: String
  },
  newState: {
    googleId: String,
    zoomUserId: String,
    accessToken: String,
    refreshToken: String,
    spreadsheetId: String
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  success: {
    type: Boolean,
    required: true
  },
  errorMessage: String
});

const AuthTracker = mongoose.model('AuthTracker', authTrackerSchema);

module.exports = AuthTracker;
