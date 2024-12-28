const { google } = require('googleapis');
const User = require('../models/User');

class GoogleAuthService {
  constructor() {
    this.oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );
  }

  async getAuthenticatedClient(userId) {
    try {
      const user = await User.findOne(userId);
      if (!user) {
        throw new Error("User not found");
      }

      this.oauth2Client.setCredentials({
        access_token: user.accessToken,
        refresh_token: user.refreshToken,
      });

      this.oauth2Client.on("tokens", async (tokens) => {
        if (tokens.refresh_token) {
          user.refreshToken = tokens.refresh_token;
        }
        user.accessToken = tokens.access_token;
        await user.save();
      });

      return this.oauth2Client;
    } catch (err) {
      console.error("Error in getAuthenticatedClient:", err);
      throw err;
    }
  }
}

// Export a singleton instance
module.exports = new GoogleAuthService();