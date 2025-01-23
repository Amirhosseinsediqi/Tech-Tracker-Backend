const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  primaryEmail: { 
    type: String, 
    required: true 
  },
  google: {
    id: String,
    email: String,
    accessToken: String,
    refreshToken: String,
    lastLogin: Date
  },
  zoom: {
    id: String,
    email: String,
    accessToken: String,
    refreshToken: String,
    tokenExpiration: Date,
    lastLogin: Date
  },
  profile: {
    name: String,
    username: String,
    createdAt: { 
      type: Date, 
      default: Date.now 
    },
    lastActivity: Date
  },
  settings: {
    spreadsheetId: String
  }
}, {
  timestamps: true
});

// Indexes
userSchema.index({ primaryEmail: 1 });
userSchema.index({ 'google.id': 1 }, { sparse: true });
userSchema.index({ 'google.email': 1 }, { sparse: true });
userSchema.index({ 'zoom.id': 1 }, { sparse: true });
userSchema.index({ 'zoom.email': 1 }, { sparse: true });

// Instance methods
userSchema.methods.updateGoogleAuth = function(profile, tokens) {
  this.google = {
    id: profile.id,
    email: profile.emails[0].value,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    lastLogin: new Date()
  };
  
  if (!this.primaryEmail) {
    this.primaryEmail = profile.emails[0].value;
  }
  
  if (!this.profile.name) {
    this.profile.name = profile.displayName;
  }
  
  return this.save();
};

userSchema.methods.updateZoomAuth = function(profile, tokens) {
  this.zoom = {
    id: profile.id,
    email: profile.email,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    tokenExpiration: new Date(Date.now() + tokens.expires_in * 1000),
    lastLogin: new Date()
  };
  
  return this.save();
};

userSchema.methods.disconnectZoom = function() {
  this.zoom = undefined;
  return this.save();
};

userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.google?.accessToken;
  delete obj.google?.refreshToken;
  delete obj.zoom?.accessToken;
  delete obj.zoom?.refreshToken;
  return obj;
};

// Static methods
userSchema.statics.findByGoogleId = function(googleId) {
  return this.findOne({ 'google.id': googleId });
};

userSchema.statics.findByZoomId = function(zoomId) {
  return this.findOne({ 'zoom.id': zoomId });
};

userSchema.statics.findByEmail = function(email) {
  return this.findOne({
    $or: [
      { primaryEmail: email },
      { 'google.email': email },
      { 'zoom.email': email }
    ]
  });
};

module.exports = mongoose.model("User", userSchema);
