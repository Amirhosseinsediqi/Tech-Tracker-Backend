const { google } = require("googleapis");
const { getAuthenticatedClient } = require("../index");
const User = require("../models/User");

async function createSheetIfNotExist(userId) {
  try {
    const auth = await getAuthenticatedClient(userId);
    const sheets = google.sheets({ version: "v4", auth });

    // بررسی اینکه آیا شیت ID در MongoDB ذخیره شده است یا خیر
    const user = await User.findById(userId);
    if (user.spreadsheetId) {
      console.log("Spreadsheet ID found in database.");
      return user.spreadsheetId;
    }

    // شیت جدیدی ایجاد کنید با عنوان "Zoom Tracker Report"
    const response = await sheets.spreadsheets.create({
      resource: {
        properties: {
          title: "Zoom Tracker Report",
        },
      },
      auth,
    });

    const spreadsheetId = response.data.spreadsheetId;

    // ذخیره spreadsheetId در MongoDB برای کاربر
    user.spreadsheetId = spreadsheetId;
    await user.save();

    console.log("Created new spreadsheet with ID:", spreadsheetId);
    return spreadsheetId;
  } catch (error) {
    console.error("Error creating or fetching spreadsheet:", error);
    throw error;
  }
}

async function appendData(userId, meetingId, data) {
  try {
    const auth = await getAuthenticatedClient(userId);
    const spreadsheetId = await createSheetIfNotExist(userId);
    const sheets = google.sheets({ version: "v4", auth });

    // نام شیت مورد نظر را از meetingNames بگیرید
    const sheetName = meetingNames[meetingId]?.name || "Sheet1";

    // بررسی و ایجاد شیت با نام مشخص شده در شیت کاربر
    const sheetMetadata = await sheets.spreadsheets.get({
      spreadsheetId,
    });

    const sheetExists = sheetMetadata.data.sheets.some(
      (sheet) => sheet.properties.title === sheetName
    );

    if (!sheetExists) {
      await sheets.spreadsheets.batchUpdate({
        spreadsheetId,
        resource: {
          requests: [
            {
              addSheet: {
                properties: {
                  title: sheetName,
                  gridProperties: {
                    rowCount: 1000,
                    columnCount: 26,
                  },
                },
              },
            },
          ],
        },
      });
      console.log(`Created new sheet: ${sheetName}`);
    }

    // افزودن داده‌ها به شیت
    const existingData = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range: `${sheetName}!A1:Z1000`,
    });

    const existingValues = existingData.data.values || [];
    const mergedData = [...existingValues, ...data];

    await sheets.spreadsheets.values.update({
      spreadsheetId,
      range: `${sheetName}!A1:Z1000`,
      valueInputOption: "RAW",
      resource: { values: mergedData },
    });

    console.log(`Data added to spreadsheet for user ${userId}`);
  } catch (error) {
    console.error("Error appending data to Google Sheet:", error);
  }
}

module.exports = { appendData, createSheetIfNotExist };
