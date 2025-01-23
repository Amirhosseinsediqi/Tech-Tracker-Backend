db = db.getSiblingDB('meetings');

// Drop existing indexes
db.users.dropIndexes();

// Create new indexes
db.users.createIndex({ "email": 1, "googleId": 1 }, { sparse: true });
db.users.createIndex({ "zoomEmail": 1, "zoomUserId": 1 }, { sparse: true });
