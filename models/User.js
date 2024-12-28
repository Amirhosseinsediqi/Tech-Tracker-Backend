const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  googleId: { type: String, required: false, unique: true, sparse: true },
  username: { type: String, required: false },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false },
  accessToken: { type: String },
  refreshToken: { type: String },
  spreadsheetId: { type: String },
  zoomUserId: { type: String, unique: true, sparse: true },
  zoomEmail: { type: String, sparse: true },
  zoomAccessToken: { type: String },
  zoomRefreshToken: { type: String },
  zoomTokenExpiration: { type: Date },
  createdAt: { type: Date, default: Date.now },
});

userSchema.index({ googleId: 1 }, { sparse: true });
userSchema.index({ email: 1 }, { unique: true });

module.exports = mongoose.model("User", userSchema);
