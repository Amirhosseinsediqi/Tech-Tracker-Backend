const axios = require("axios");
const fs = require("fs");
const path = require("path");
const { Parser } = require("json2csv");
const csv = require("csv-parser");
const { google } = require("googleapis");
const momentTimezone = require("moment-timezone");
const moment = require("moment");
const momentJalaali = require("moment-jalaali");
const getAuthenticatedClient = require("../../auth/googleAuth.js");
const mongoose = require("mongoose");
const TIMEZONE = "Asia/Tehran";
const User = require("../../models/User");
const ProcessedMeeting = require("../../models/ProcessedMeeting");
const { Meeting, getMeetingDetailsFromDB } = require("../../utils/meetingHelper");
const { refreshZoomToken, validateZoomToken } = require("../../index.js");
const downloadJsonDir = "/app/downloads";
const savedCsvDir = "/app/savedCsv";
const processedCsvDir = "/app/csvProcessed";

const meetingSchema = new mongoose.Schema({
  id: Number,
  name: String,
  delayPercentage: Number,
  createdAt: { type: Number, default: Date.now() },
  allowTime: Number,
});

async function findOrCreateSpreadsheet(auth, user) {
  const sheets = google.sheets({ version: "v4", auth });
  const drive = google.drive({ version: "v3", auth });
  const maxRetries = 3;
  const retryDelay = 2000;

  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // First, try to get the spreadsheet ID from the Google user's document
  try {
    // Look for user with googleId which indicates it's a Google account
    const googleUser = await User.findOne({
      googleId: { $exists: true },
      accessToken: { $exists: true },
    });

    console.log(
      "Found Google user:",
      googleUser ? googleUser.email : "not found"
    );

    if (googleUser && googleUser.settings?.spreadsheetId) {
      console.log(
        "Found spreadsheet ID in Google user document:",
        googleUser.settings.spreadsheetId
      );

      // Verify the spreadsheet still exists and is accessible
      try {
        const exists = await verifySpreadsheetExists(
          auth,
          googleUser.settings.spreadsheetId
        );
        if (exists) {
          console.log("Verified existing spreadsheet is accessible");
          SPREADSHEET_ID = googleUser.settings.spreadsheetId;
          return SPREADSHEET_ID;
        }
        console.log("Stored spreadsheet no longer exists, creating new one");
      } catch (error) {
        console.error("Error verifying spreadsheet:", error);
        console.log("Creating new spreadsheet due to verification error");
      }
    }
  } catch (error) {
    console.error("Error checking Google user document:", error);
  }

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log(`Attempt ${attempt}: Searching for existing spreadsheet...`);

      // Log auth info (safely)
      console.log("Auth credentials type:", typeof auth.credentials);
      console.log("Auth token type:", auth.credentials.token_type);
      console.log("Using email:", auth.credentials.email);

      // More detailed search query
      const searchQuery = `mimeType='application/vnd.google-sheets.spreadsheet' and name='${process.env.SPREADSHEET_NAME}' and trashed=false`;
      console.log("Search query:", searchQuery);

      const response = await drive.files.list({
        q: searchQuery,
        fields: "files(id, name, createdTime, owners, permissions)",
        orderBy: "createdTime desc",
        pageSize: 10,
        spaces: "drive",
        corpora: "allDrives",
        includeItemsFromAllDrives: true,
        supportsAllDrives: true,
      });

      console.log("Search results:", JSON.stringify(response.data, null, 2));

      if (response.data.files && response.data.files.length > 0) {
        // Sort by creation time to get the most recent one
        const files = response.data.files.sort(
          (a, b) => new Date(b.createdTime) - new Date(a.createdTime)
        );

        SPREADSHEET_ID = files[0].id;
        console.log(`Found existing spreadsheet with ID: ${SPREADSHEET_ID}`);
        console.log(`Created time: ${files[0].createdTime}`);
        console.log(
          `Owner: ${
            files[0].owners ? files[0].owners[0].emailAddress : "unknown"
          }`
        );
        console.log(
          "Permissions:",
          JSON.stringify(files[0].permissions, null, 2)
        );

        // Store in Google user document
        try {
          const googleUser = await User.findOne({
            googleId: { $exists: true },
            accessToken: { $exists: true },
          });

          if (googleUser) {
            await User.findByIdAndUpdate(
              googleUser._id,
              { $set: { "settings.spreadsheetId": SPREADSHEET_ID } },
              { new: true }
            );
            console.log(
              "Updated spreadsheet ID for Google user:",
              googleUser.email
            );
          } else {
            console.log("No Google user found to store spreadsheet ID");
          }
        } catch (dbError) {
          console.error(
            "Failed to update spreadsheet ID in user document:",
            dbError
          );
        }

        return SPREADSHEET_ID;
      }

      console.log(
        `Attempt ${attempt}: No existing spreadsheet found. Creating new one...`
      );
      const resource = {
        properties: {
          title: process.env.SPREADSHEET_NAME,
        },
      };

      const createResponse = await sheets.spreadsheets.create({
        resource,
        fields: "spreadsheetId",
      });

      SPREADSHEET_ID = createResponse.data.spreadsheetId;
      console.log(`Created new spreadsheet with ID: ${SPREADSHEET_ID}`);

      // Store the spreadsheet ID in the Google user's document
      try {
        const googleUser = await User.findOne({
          googleId: { $exists: true },
          accessToken: { $exists: true },
        });

        if (googleUser) {
          const user = await User.findByIdAndUpdate(
            googleUser._id,
            { $set: { "settings.spreadsheetId": SPREADSHEET_ID } },
            { new: true }
          );
          console.log(
            "Stored spreadsheet ID in Google user document:",
            user.email
          );
        } else {
          console.log("No Google user found to store spreadsheet ID");
        }
      } catch (dbError) {
        console.error("Failed to store spreadsheet ID:", dbError);
      }

      return SPREADSHEET_ID;
    } catch (error) {
      console.error(`Attempt ${attempt} failed:`, error.message);

      if (error.code === 503) {
        if (attempt === maxRetries) {
          console.error("Maximum retries reached. Service still unavailable.");
          throw new Error(
            "Google Sheets service is currently unavailable. Please try again later."
          );
        }
        console.log(`Waiting ${retryDelay}ms before retry...`);
        await delay(retryDelay * attempt);
        continue;
      }

      if (error.code === 401 || error.code === 403) {
        console.error(
          "Authentication error. Token might be invalid or expired."
        );
        throw new Error(
          "Authentication failed. Please try reconnecting your Google account."
        );
      }

      throw error;
    }
  }
}

async function verifySpreadsheetExists(auth, spreadsheetId) {
  try {
    const sheets = google.sheets({ version: "v4", auth });
    await sheets.spreadsheets.get({
      spreadsheetId: spreadsheetId,
    });
    return true;
  } catch (error) {
    if (error.code === 404) {
      return false;
    }
    throw error;
  }
}

async function createMeetingSheet(auth, meetingName) {
  const sheets = google.sheets({ version: "v4", auth });

  try {
    console.log(`Checking if sheet ${meetingName} exists...`);
    const spreadsheet = await sheets.spreadsheets.get({
      spreadsheetId: SPREADSHEET_ID,
      ranges: [],
      includeGridData: false,
    });

    const sheetExists = spreadsheet.data.sheets.some(
      (sheet) => sheet.properties.title === meetingName
    );

    if (sheetExists) {
      console.log(`Sheet ${meetingName} already exists`);
      return true;
    }

    console.log(`Creating new sheet: ${meetingName}`);
    const addSheetRequest = {
      addSheet: {
        properties: {
          title: meetingName,
          gridProperties: {
            rowCount: 1000,
            columnCount: 26,
          },
        },
      },
    };

    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: {
        requests: [addSheetRequest],
      },
    });

    console.log("Initializing sheet with headers...");
    const headers = ["Absence Count", "Names"];
    await sheets.spreadsheets.values.update({
      spreadsheetId: SPREADSHEET_ID,
      range: `${meetingName}!A1:B1`,
      valueInputOption: "RAW",
      resource: {
        values: [headers],
      },
    });

    console.log("Sheet created and initialized successfully");
    return true;
  } catch (error) {
    console.error("Error in createMeetingSheet:", error);
    throw error;
  }
}

async function applyConditionalFormatting(auth, sheetName) {
  const sheets = google.sheets({ version: "v4", auth });

  const sheetMetadata = await sheets.spreadsheets.get({
    spreadsheetId: SPREADSHEET_ID,
    ranges: [],
    includeGridData: false,
  });

  const sheet = sheetMetadata.data.sheets.find(
    (sheet) => sheet.properties.title === sheetName
  );
  if (!sheet) {
    console.error(`Sheet ${sheetName} not found.`);
    return;
  }

  const sheetId = sheet.properties.sheetId;
  console.log(`Applying conditional formatting to sheet ID: ${sheetId}`);

  const requests = [
    {
      addConditionalFormatRule: {
        rule: {
          ranges: [
            {
              sheetId: sheetId,
              startRowIndex: 1,
              endRowIndex: 1000,
              startColumnIndex: 0,
              endColumnIndex: 1,
            },
          ],
          booleanRule: {
            condition: {
              type: "NUMBER_EQ",
              values: [{ userEnteredValue: "3" }],
            },
            format: {
              backgroundColor: {
                red: 1.0,
                green: 1.0,
                blue: 0.0,
              },
            },
          },
        },
        index: 0,
      },
    },
    {
      addConditionalFormatRule: {
        rule: {
          ranges: [
            {
              sheetId: sheetId,
              startRowIndex: 1,
              endRowIndex: 1000, // Adjust as needed
              startColumnIndex: 0,
              endColumnIndex: 1,
            },
          ],
          booleanRule: {
            condition: {
              type: "NUMBER_GREATER",
              values: [{ userEnteredValue: "3" }],
            },
            format: {
              backgroundColor: {
                red: 1.0,
                green: 0.0,
                blue: 0.0,
              },
            },
          },
        },
        index: 1,
      },
    },
  ];

  try {
    const response = await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SPREADSHEET_ID,
      resource: { requests },
    });
    console.log(
      `Conditional formatting applied: ${JSON.stringify(response.data)}`
    );
  } catch (error) {
    console.error(`Error applying conditional formatting: ${error.message}`);
  }
}

async function getStudentNames(auth, sheetName) {
  const sheets = google.sheets({ version: "v4", auth });

  try {
    // First, get the spreadsheet ID if not already set
    if (!SPREADSHEET_ID) {
      const response = await sheets.spreadsheets.list();
      const spreadsheet = response.data.files.find(
        (file) => file.name === process.env.SPREADSHEET_NAME
      );
      if (spreadsheet) {
        SPREADSHEET_ID = spreadsheet.id;
      } else {
        throw new Error("Spreadsheet not found");
      }
    }

    const range = `${sheetName}!A:B`; // Assuming names are in column A or B
    const response = await sheets.spreadsheets.values.get({
      spreadsheetId: SPREADSHEET_ID,
      range,
    });

    const rows = response.data.values || [];
    console.log("Retrieved rows from sheet:", rows.length);

    // Skip header row and extract names, removing empty values
    const names = rows
      .slice(1)
      .map((row) => row[1]) // Get name from second column
      .filter((name) => name && name.trim() !== "");

    console.log("Extracted student names:", names.length);
    return names;
  } catch (error) {
    console.error("Error fetching student names:", error);
    return [];
  }
}

function getPreviousMeetingColumns(header, currentDateColumn) {
  const meetingColumns = [];

  for (let i = 0; i < header.length; i++) {
    // Check if the header item is a string and starts with 'Attendance '
    if (
      header[i] &&
      typeof header[i] === "string" &&
      header[i].startsWith("Attendance ")
    ) {
      meetingColumns.push({
        dateColumn: i,
        reasonColumn: i + 1,
        date: header[i].replace("Attendance ", ""),
      });
    }
  }

  // Sort by date (assuming Jalaali date format)
  meetingColumns.sort((a, b) => {
    const dateA = momentJalaali(a.date.split(" - ")[0], "jYYYY/jMM/jDD");
    const dateB = momentJalaali(b.date.split(" - ")[0], "jYYYY/jMM/jDD");
    return dateA.valueOf() - dateB.valueOf();
  });

  // Find current meeting index
  const currentIndex = meetingColumns.findIndex(
    (col) => header[col.dateColumn] === currentDateColumn
  );

  // Return all meetings before current one
  return meetingColumns.slice(0, currentIndex);
}

function handleRetroactiveAbsences(rows, header, nameIndex, dateIndex) {
  const previousMeetings = getPreviousMeetingColumns(header, header[dateIndex]);
  let absencesAdded = 0;

  // For each previous meeting column
  previousMeetings.forEach((meeting) => {
    // If the cell is empty or not marked
    if (
      !rows[nameIndex][meeting.dateColumn] ||
      rows[nameIndex][meeting.dateColumn] === ""
    ) {
      // Mark as absent
      rows[nameIndex][meeting.dateColumn] = "1";
      // Set reason with explicit pre-enrollment note
      rows[nameIndex][meeting.reasonColumn] =
        "Did not attend (0%) - Not yet enrolled";
      // Increment total absence count
      rows[nameIndex][0] = (Number(rows[nameIndex][0]) || 0) + 1;
      absencesAdded++;
    }
  });

  return absencesAdded;
}

const updateAbsenceCount = async (
  auth,
  sheetName,
  filePath,
  date,
  meetingConfig
) => {
  const sheets = google.sheets({ version: "v4", auth });
  const range = `${sheetName}!A:ZZ`;

  const momentDate = momentTimezone.tz(date, TIMEZONE);
  const formattedDateTime = momentTimezone
    .tz(date, TIMEZONE)
    .format("YYYY-MM-DD - HH:mm");
  const formattedJalaaliDateTime = momentJalaali(
    formattedDateTime,
    "YYYY-MM-DD - HH:mm"
  ).format("jYYYY-jMM-jDD - HH:mm");

  const dateColumnName = `Attendance ${formattedJalaaliDateTime}`;
  const reasonColumnName = `Reasons ${formattedJalaaliDateTime}`;
  const percentageColumnName = `Attendance percentage`;

  console.log("Processing sheet:", sheetName);
  console.log("Date column:", dateColumnName);

  // Get current meeting's participants
  const participants = await readCsvFile(filePath);
  const processedParticipants = aggregateDurations(participants);

  console.log("Processed participants:", processedParticipants);

  // Get the list of expected students from the sheet
  const sheetNames = await getStudentNames(auth, sheetName);
  console.log("Expected students from sheet:", sheetNames);

  // Get current sheet data
  const response = await sheets.spreadsheets.values.get({
    spreadsheetId: SPREADSHEET_ID,
    range,
  });

  let rows = response.data.values || [];
  let header = rows[0] || ["Total Absences", "Name"];

  // Sort attendance columns chronologically
  const attendanceColumns = [];
  for (let i = 2; i < header.length; i += 3) {
    // Changed from i += 2 to i += 3 to account for new percentage column
    const col = header[i];
    if (col && typeof col === "string" && col.startsWith("Attendance ")) {
      attendanceColumns.push({
        attendanceIndex: i,
        reasonIndex: i + 1,
        percentageIndex: i + 2,
        date: col.replace("Attendance ", ""),
      });
    }
  }

  let dateIndex = header.indexOf(dateColumnName);
  const isNewSession = dateIndex === -1;

  // Add new columns for the current meeting if they don't exist
  if (isNewSession) {
    header.push(dateColumnName, reasonColumnName, percentageColumnName); // Added percentage column
    dateIndex = header.length - 3; // Updated index calculation

    // Add the new column to our tracking
    attendanceColumns.push({
      attendanceIndex: dateIndex,
      reasonIndex: dateIndex + 1,
      percentageIndex: dateIndex + 2,
      date: formattedJalaaliDateTime,
    });
  }

  // Ensure header row exists and has proper length
  if (rows.length === 0) {
    rows.push(header);
  } else {
    rows[0] = header;
    // Ensure all existing rows have the proper length
    for (let i = 1; i < rows.length; i++) {
      while (rows[i].length < header.length) {
        rows[i].push("");
      }
    }
  }

  // Process all expected students from the sheet
  for (const studentName of sheetNames) {
    let nameIndex = rows.findIndex(
      (row) =>
        row && row[1] && normalizeName(row[1]) === normalizeName(studentName)
    );

    // If this is a new expected student
    if (nameIndex === -1) {
      // Create new row initialized with empty strings
      const newRow = new Array(header.length).fill("");
      newRow[0] = "0"; // Total absences
      newRow[1] = studentName; // Name

      // Record enrollment date
      const enrollmentDate = momentTimezone
        .tz(date, TIMEZONE)
        .format("jYYYY-jMM-jDD");

      let previousAbsences = 0;
      // Mark all previous sessions as absent
      attendanceColumns.forEach((col) => {
        // Skip the current session
        if (col.attendanceIndex !== dateIndex) {
          newRow[col.attendanceIndex] = "1"; // Mark as absent
          newRow[col.reasonIndex] = "Did not attend"; // Removed percentage from reason
          newRow[col.percentageIndex] = "0"; // Set percentage to 0
          previousAbsences++;
        }
      });

      newRow[0] = previousAbsences.toString();
      rows.push(newRow);
      nameIndex = rows.length - 1;
    }

    // Process current session attendance
    const participant = processedParticipants.find(
      (p) => normalizeName(p.name) === normalizeName(studentName)
    );

    if (participant) {
      // Use the minutes late value calculated in aggregateDurations
      const minutesLate = participant.minutesLate;
      console.log(`${participant.name} joined at ${participant.firstJoinTime.format()} - ${minutesLate} minutes after session start`);

      const isLate = minutesLate > (meetingConfig.allowTime || 10);
      const isAbsent = isLate || participant.attendancePercentage < (meetingConfig.delayPercentage || 70);
      
      // Set attendance status
      rows[nameIndex][dateIndex] = isAbsent ? "1" : "0";

      // Set attendance status and reason
      let reasons = [];
      
      // Check for lateness first
      if (isLate) {
        reasons.push(`Late[${minutesLate}min]`);
      }
      
      // Check attendance second
      if (participant.attendancePercentage < (meetingConfig.delayPercentage || 70)) {
        if (participant.attendancePercentage === 0) {
          reasons.push("Did not attend");
        } else {
          reasons.push(`Insufficient attendance`);
        }
      }
      
      // If no reasons (means they were present and on time)
      if (reasons.length === 0) {
        reasons.push("Present");
      }
      
      console.log(`Final reasons for ${participant.name}:`, reasons);
      
      // Combine all reasons with " - "
      rows[nameIndex][dateIndex + 1] = reasons.join(" - ");
      rows[nameIndex][dateIndex + 2] = `${participant.attendancePercentage}%`;

    } else {
      // Expected student did not attend current session
      rows[nameIndex][dateIndex] = "1";
      rows[nameIndex][dateIndex + 1] = "Did not attend";
      rows[nameIndex][dateIndex + 2] = "0%";
    }

    // Update total absences
    const totalAbsences = attendanceColumns.reduce((sum, col) => {
      return sum + (rows[nameIndex][col.attendanceIndex] === "1" ? 1 : 0);
    }, 0);

    rows[nameIndex][0] = totalAbsences.toString();
  }

  // Process unexpected participants
  const meetingParticipants = processedParticipants.map((p) => ({
    name: p.name,
    normalized: normalizeName(p.name),
    data: p,
  }));

  for (const participant of meetingParticipants) {
    const isExpectedStudent = sheetNames.some(
      (name) => normalizeName(name) === participant.normalized
    );
    if (isExpectedStudent) continue;

    let nameIndex = rows.findIndex(
      (row) => row && row[1] && normalizeName(row[1]) === participant.normalized
    );

    if (nameIndex === -1) {
      const newRow = new Array(header.length).fill("");
      newRow[0] = "0";
      newRow[1] = participant.name;

      // For unexpected participants, mark previous sessions
      attendanceColumns.forEach((col) => {
        if (col.attendanceIndex !== dateIndex) {
          newRow[col.attendanceIndex] = "0";
          newRow[col.reasonIndex] = "Not Expected";
          newRow[col.percentageIndex] = "0%";
        }
      });

      rows.push(newRow);
      nameIndex = rows.length - 1;
    }

    // Process current session attendance
    const minutesLate = Math.max(0, participant.data.minutesLate); // Ensure positive minutes
    const isLate = minutesLate > (meetingConfig.allowTime || 10);
    const isAbsent = isLate || participant.data.attendancePercentage < (meetingConfig.delayPercentage || 70);
    
    // Set attendance status
    rows[nameIndex][dateIndex] = isAbsent ? "1" : "0";

    // Set attendance status and reason
    let reasons = [];
    
    // Check for lateness first
    if (isLate) {
      reasons.push(`Late[${minutesLate}min]`);
    }
    
    // Check attendance second
    if (participant.data.attendancePercentage < (meetingConfig.delayPercentage || 70)) {
      if (participant.data.attendancePercentage === 0) {
        reasons.push("Did not attend");
      } else {
        reasons.push("Insufficient attendance");
      }
    }
    
    // If no reasons (means they were present and on time)
    if (reasons.length === 0) {
      reasons.push("Present");
    }
    
    // Combine all reasons with " - "
    rows[nameIndex][dateIndex + 1] = reasons.join(" - ");
    rows[nameIndex][dateIndex + 2] = `${participant.data.attendancePercentage}%`;

    // Update total absences
    const totalAbsences = attendanceColumns.reduce((sum, col) => {
      const reason = rows[nameIndex][col.reasonIndex];
      if (!reason || !reason.includes("N/A")) {
        return sum + (rows[nameIndex][col.attendanceIndex] === "1" ? 1 : 0);
      }
      return sum;
    }, 0);
    rows[nameIndex][0] = totalAbsences.toString();
  }

  // Update the sheet
  await sheets.spreadsheets.values.update({
    spreadsheetId: SPREADSHEET_ID,
    range,
    valueInputOption: "RAW",
    resource: {
      values: rows,
    },
  });

  console.log(`Updated absence counts for sheet: ${sheetName}`);
  await applyConditionalFormatting(auth, sheetName);
};

function normalizeName(name) {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-zA-Z0-9]/g, "");
}

function findSimilarName(normalizedNames, targetName) {
  for (let name of normalizedNames) {
    if (name.includes(targetName) || targetName.includes(name)) {
      return name;
    }
  }
  return null;
}

function readCsvFile(filePath) {
  return new Promise((resolve, reject) => {
    const results = [];
    fs.createReadStream(filePath)
      .pipe(
        csv({
          mapHeaders: ({ header }) => header.toLowerCase().trim(),
        })
      )
      .on("data", (data) => results.push(data))
      .on("end", () => {
        console.log("CSV headers:", Object.keys(results[0])); // Debug statement to show headers
        resolve(results);
      })
      .on("error", (error) => reject(error));
  });
}

function aggregateDurations(participants) {
  let firstJoin = null;
  let lastLeave = null;
  const durationMap = new Map();
  const normalizedNamesMap = new Map();

  // First pass: find the actual meeting duration
  participants.forEach((participant) => {
    const joinTime = momentTimezone.tz(participant["join_time"], TIMEZONE);
    const leaveTime = momentTimezone.tz(participant["leave_time"], TIMEZONE);
    
    if (!firstJoin || joinTime.isBefore(firstJoin)) {
      firstJoin = joinTime;
    }
    if (!lastLeave || leaveTime.isAfter(lastLeave)) {
      lastLeave = leaveTime;
    }
  });

  // Calculate actual meeting duration in minutes
  const actualMeetingDuration = lastLeave.diff(firstJoin, 'minutes');
  console.log(`Actual meeting duration (from first join to last leave): ${actualMeetingDuration} minutes`);

  // Get the first participant's join time to use as session start
  const firstParticipantJoinTime = momentTimezone.tz(participants[0]["join_time"], TIMEZONE);

  // Process each participant
  participants.forEach((participant) => {
    const originalName = participant["name"];
    const normalizedName = normalizeName(originalName);
    const durationInMinutes = parseInt(participant["duration"], 10);
    const joinTime = momentTimezone.tz(participant["join_time"], TIMEZONE);
    
    // Calculate minutes late based on first participant's join time
    const minutesLate = participant["name"] === participants[0]["name"] ? 0 : 
      Math.max(0, joinTime.diff(firstParticipantJoinTime, 'minutes'));

    // Find if this participant already exists under a similar name
    let existingName = null;
    for (const [existing] of normalizedNamesMap) {
      if (findSimilarName([existing], normalizedName)) {
        existingName = existing;
        break;
      }
    }

    // Use existing name or create new entry
    const nameToUse = existingName || normalizedName;
    
    // If this is a new name, initialize the map entries
    if (!normalizedNamesMap.has(nameToUse)) {
      normalizedNamesMap.set(nameToUse, originalName);
      durationMap.set(nameToUse, {
        originalName,
        duration: 0,
        firstJoinTime: joinTime,
        minutesLate: minutesLate,
        sessions: []
      });
    }

    // Get the existing data
    const participantData = durationMap.get(nameToUse);

    // Update the data
    participantData.duration += durationInMinutes;
    participantData.sessions.push({
      joinTime,
      duration: durationInMinutes,
      minutesLate
    });

    // Keep the earliest join time and its corresponding minutesLate
    if (joinTime.isBefore(participantData.firstJoinTime)) {
      participantData.firstJoinTime = joinTime;
      participantData.minutesLate = minutesLate;
    }

    console.log(`Processing ${originalName} (as ${nameToUse}): {
      duration: ${durationInMinutes},
      totalDuration: ${participantData.duration},
      joinTime: ${joinTime.format()},
      minutesLate: ${minutesLate},
      sessions: ${participantData.sessions.length}
    }`);
  });

  // Convert the map to the required output format
  return Array.from(durationMap.entries()).map(([normalizedName, data]) => {
    // Calculate attendance percentage based on actual meeting duration
    const attendancePercentage = Math.min(100, Math.round(
      (data.duration / actualMeetingDuration) * 100
    ));

    console.log(`${data.originalName} final calculations: {
      normalizedName: ${normalizedName},
      duration: ${data.duration},
      actualMeetingDuration: ${actualMeetingDuration},
      attendancePercentage: ${attendancePercentage},
      minutesLate: ${data.minutesLate},
      sessions: ${data.sessions.length}
    }`);

    return {
      name: data.originalName,
      duration: data.duration,
      firstJoinTime: data.firstJoinTime,
      attendancePercentage,
      minutesLate: data.minutesLate,
      isLate: data.minutesLate > 10
    };
  });
}

async function processZoomParticipation(
  file_path,
  output_directory,
  meetingId
) {
  try {
    console.log("Received meetingId:", meetingId);
    const meetingConfig = await getMeetingDetailsFromDB(meetingId);

    if (!meetingConfig) {
      throw new Error(`Meeting configuration not found for ID: ${meetingId}`);
    }

    console.log(
      `Allowed time for meeting ${meetingId} (${meetingConfig.name}): ${meetingConfig.allowTime} minutes`
    );
    console.log(`Processing meeting: ${meetingConfig.name} (ID: ${meetingId})`);

    const rawData = JSON.parse(fs.readFileSync(file_path, "utf8"));
    const participants = rawData.participants || [];

    // Process participants
    const processedParticipants = participants.map((participant) => {
      const joinTime = momentTimezone.tz(participant["join_time"], TIMEZONE);
      const firstParticipantTime = momentTimezone.tz(
        participants[0].join_time,
        TIMEZONE
      );
      const duration = Math.round(participant.duration / 60); // Convert to minutes
      
      // Calculate minutes late
      const minutesLate = participant.name === participants[0].name ? 0 : 
        Math.max(0, joinTime.diff(firstParticipantTime, 'minutes'));

      console.log(`${participant.name} joined at ${joinTime.format()} - ${minutesLate} minutes after session start`);

      return {
        id: participant.id,
        name: participant.name || participant.user_name,
        user_email: participant.user_email || "",
        join_time: participant.join_time,
        leave_time: participant.leave_time,
        duration: duration.toString(),
        Status: duration > 0 ? "Present" : "Absent",
        minutesLate: minutesLate.toString(),
        isLate: minutesLate > (meetingConfig.allowTime || 10),
        attendancePercentage: Math.round((duration / Math.max(1, rawData.duration)) * 100)
      };
    });

    // Save to CSV
    const outputPath = path.join(
      output_directory,
      `processed_${meetingId}_participants.csv`
    );
    const fields = [
      "id",
      "name",
      "user_email",
      "join_time",
      "leave_time",
      "duration",
      "Status",
      "minutesLate",
      "isLate",
      "attendancePercentage"
    ];
    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(processedParticipants);

    fs.writeFileSync(outputPath, csv, "utf8");
    console.log(`Processed data saved to: ${outputPath}`);

    return outputPath;
  } catch (error) {
    console.error(`Error processing meeting ${meetingId}:`, error);
    throw error;
  }
}

async function validateGoogleToken(accessToken) {
  try {
    const response = await axios.get(
      "https://www.googleapis.com/oauth2/v3/tokeninfo",
      {
        params: { access_token: accessToken },
      }
    );
    return (
      response.data &&
      response.data.scope &&
      response.data.scope
        .split(" ")
        .includes("https://www.googleapis.com/auth/drive.file")
    );
  } catch (error) {
    console.log(
      "Token validation failed:",
      error.response?.data || error.message
    );
    return false;
  }
}

async function refreshGoogleToken(oauth2Client, user) {
  try {
    // Set up form data
    const formData = new URLSearchParams();
    formData.append("client_id", process.env.GOOGLE_CLIENT_ID);
    formData.append("client_secret", process.env.GOOGLE_CLIENT_SECRET);
    formData.append("grant_type", "refresh_token");
    formData.append("refresh_token", user.google.refreshToken);

    const response = await axios.post(
      "https://oauth2.googleapis.com/token",
      formData.toString(),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const { access_token, refresh_token } = response.data;

    // Update user's tokens in database
    user.google.accessToken = access_token;
    if (refresh_token) {
      user.google.refreshToken = refresh_token;
    }
    await user.save();

    // Update oauth client
    oauth2Client.setCredentials({
      access_token: access_token,
      refresh_token: user.google.refreshToken,
    });

    return true;
  } catch (error) {
    console.error(
      "Token refresh failed:",
      error.response?.data || error.message
    );
    return false;
  }
}

async function handleMeetingParticipantsReport(
  meetingId,
  userId,
  meetingDetails
) {
  try {
    // First get the participants data to check duration
    console.log("Fetching participants for meeting:", meetingId);
    console.log("Meeting details:", {
      meetingId,
      userId,
      accountId: meetingDetails.accountId,
      hostId: meetingDetails.hostId
    });

    const participantsUrl = `${process.env.ZOOM_API_URL}/past_meetings/${meetingId}/participants`;
    console.log("Requesting participants from URL:", participantsUrl);

    // Add account_id to query params if it's a subaccount
    const params = {};
    if (meetingDetails.accountId) {
      params.account_id = meetingDetails.accountId;
    }

    const participantsResponse = await axios.get(participantsUrl, {
      headers: {
        Authorization: `Bearer ${meetingDetails.accessToken}`,
        "Content-Type": "application/json",
      },
      params: params
    });

    if (!participantsResponse.data || !participantsResponse.data.participants) {
      console.error(
        "Invalid response from Zoom API:",
        participantsResponse.data
      );
      throw new Error("Invalid response from Zoom API");
    }

    // Log the response for debugging
    console.log("Zoom API Response Headers:", participantsResponse.headers);
    console.log("Number of participants:", participantsResponse.data.participants.length);

    const participants = participantsResponse.data.participants;
    if (participants.length === 0) {
      console.log(
        `Meeting ${meetingId} has no participants. Skipping processing.`
      );
      return;
    }

    // Calculate meeting duration
    const joinTimes = participants.map((p) => new Date(p.join_time).getTime());
    const leaveTimes = participants.map((p) =>
      new Date(p.leave_time).getTime()
    );
    const meetingStart = Math.min(...joinTimes);
    const meetingEnd = Math.max(...leaveTimes);
    const totalDurationMinutes = Math.round(
      (meetingEnd - meetingStart) / (60 * 1000)
    );

    // Check if meeting was already processed within a window of the meeting's end time
    const meetingEndTime = new Date(meetingDetails.endTime);
    const existingProcessing = await ProcessedMeeting.findOne({
      meetingId,
      $or: [
        // Check if processed within 10 minutes of meeting end
        {
          processedAt: {
            $gte: new Date(meetingEndTime.getTime() - 10 * 60 * 1000),
            $lte: new Date(meetingEndTime.getTime() + 10 * 60 * 1000)
          }
        },
        // Or if processed very recently (within last 2 minutes) regardless of meeting end time
        {
          processedAt: {
            $gte: new Date(new Date().getTime() - 2 * 60 * 1000)
          }
        }
      ]
    });

    if (existingProcessing && !existingProcessing.skippedDueToShortDuration) {
      console.log(
        `Meeting ${meetingId} was already processed at ${existingProcessing.processedAt}`
      );
      console.log(
        `Time since meeting end: ${
          (new Date(meetingEndTime) - existingProcessing.processedAt) / (60 * 1000)
        } minutes`
      );
      return;
    }

    // Check duration after deduplication check
    if (totalDurationMinutes < 10) {
      console.log(
        `Meeting ${meetingId} duration (${totalDurationMinutes} minutes) is less than 10 minutes. Skipping processing.`
      );

      // Save record that this meeting was skipped due to short duration
      await ProcessedMeeting.create({
        meetingId,
        userId,
        processedAt: new Date(),
        meetingDate: new Date(meetingStart),
        skippedDueToShortDuration: true,
      });

      return;
    }

    console.log(
      `Meeting ${meetingId} duration: ${totalDurationMinutes} minutes. Proceeding with processing.`
    );

    // Get meeting configuration
    const meetingConfig = await getMeetingDetailsFromDB(meetingId);
    if (!meetingConfig) {
      console.error(
        `Meeting configuration for meeting ID ${meetingId} not found in database.`
      );
      return;
    }

    if (!meetingDetails.accessToken) {
      throw new Error("Zoom access token not found in meeting details");
    }

    // Verify token works with Zoom API
    try {
      await axios.get("https://api.zoom.us/v2/users/me", {
        headers: {
          Authorization: `Bearer ${meetingDetails.accessToken}`,
        },
      });
    } catch (error) {
      console.error(
        "Token verification failed:",
        error.response?.data || error.message
      );
      throw new Error("Invalid Zoom access token");
    }

    // Fetch participants from Zoom API (using existing participantsUrl)
    console.log("Requesting participants from URL:", participantsUrl);

    const request = await axios.get(participantsUrl, {
      headers: {
        Authorization: `Bearer ${meetingDetails.accessToken}`,
        "Content-Type": "application/json",
      },
      params: {
        page_size: 300,
        next_page_token: "",
      },
    });

    if (!request.data || !request.data.participants) {
      console.error("Invalid response from Zoom API:", request.data);
      throw new Error("Invalid response from Zoom API");
    }

    console.log(`Retrieved ${request.data.participants.length} participants`);

    // Save raw data
    const jsonFilePath = path.join(
      downloadJsonDir,
      `${meetingId}_participants.json`
    );
    const csvFilePath = path.join(savedCsvDir, `${meetingId}_participants.csv`);
    const processedCsvFilePath = path.join(
      processedCsvDir,
      `processed_${meetingId}_participants.csv`
    );

    // Ensure directories exist
    [downloadJsonDir, savedCsvDir, processedCsvDir].forEach((dir) => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });

    // Save JSON file
    console.log("Saving JSON file:", jsonFilePath);
    fs.writeFileSync(
      jsonFilePath,
      JSON.stringify(request.data, null, 2),
      "utf8"
    );

    // Process Zoom participants
    console.log("Processing participants data...");
    await processZoomParticipation(jsonFilePath, processedCsvDir, meetingId);

    // Find user with Google access token
    const googleUser = await User.findOne({
      $or: [
        { google: { $exists: true } },
        { "google.accessToken": { $exists: true } },
        { "google.refreshToken": { $exists: true } },
      ],
    });

    if (!googleUser) {
      throw new Error(
        "No user found with Google credentials. Please connect a Google account first."
      );
    }

    if (!googleUser.google.accessToken && !googleUser.google.refreshToken) {
      throw new Error(
        "Google credentials are missing. Please reconnect your Google account."
      );
    }

    console.log("Setting up Google OAuth client...");
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );

    // Set tokens
    oauth2Client.setCredentials({
      access_token: googleUser.google.accessToken,
      refresh_token: googleUser.google.refreshToken,
    });

    // Validate current access token
    let isAuthenticated = false;
    if (googleUser.google.accessToken) {
      console.log("Validating Google access token...");
      isAuthenticated = await validateGoogleToken(googleUser.google.accessToken);
    }

    // If access token is invalid and we have a refresh token, try refreshing
    if (!isAuthenticated && googleUser.google.refreshToken) {
      console.log("Access token invalid, attempting to refresh...");
      isAuthenticated = await refreshGoogleToken(oauth2Client, googleUser);
    }

    if (!isAuthenticated) {
      throw new Error(
        "Google authentication failed. Please try reconnecting your Google account with both access and refresh tokens."
      );
    }

    console.log("Google OAuth client setup complete");

    // Find or create the main spreadsheet
    console.log("Finding or creating main spreadsheet...");
    const spreadsheetId = await findOrCreateSpreadsheet(oauth2Client, googleUser);

    // Create sheet for this meeting
    console.log(`Creating sheet for meeting: ${meetingConfig.name}`);
    await createMeetingSheet(oauth2Client, meetingConfig.name);

    // Update attendance data
    console.log("Updating attendance data...");
    await updateAbsenceCount(
      oauth2Client,
      meetingConfig.name,
      processedCsvFilePath,
      meetingDetails.startTime,
      meetingConfig
    );

    // Apply conditional formatting
    console.log("Applying conditional formatting...");
    await applyConditionalFormatting(oauth2Client, meetingConfig.name);

    console.log("Meeting participant report processing completed successfully");

    // After successful processing, record it
    await ProcessedMeeting.create({
      meetingId,
      userId,
      meetingDate: meetingDetails.startTime || new Date(),
    });
  } catch (error) {
    console.error("Error in handleMeetingParticipantsReport:", error);
    throw error;
  }
}

module.exports = handleMeetingParticipantsReport;
