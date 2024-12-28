const mongoose = require("mongoose");
const User = require("./User");

const ProcessedMeetingSchema = new mongoose.Schema({
  meetingId: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  processedAt: {
    type: Date,
    default: Date.now
  },
  meetingDate: {
    type: Date,
    required: true
  },
  skippedDueToShortDuration: {
    type: Boolean,
    default: false
  }
});

// Create a compound index on meetingId and processedAt
// This allows multiple records for the same meetingId but helps with querying recent ones
ProcessedMeetingSchema.index({ 
  meetingId: 1, 
  processedAt: -1 
});

module.exports = mongoose.model('ProcessedMeeting', ProcessedMeetingSchema);