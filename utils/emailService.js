const nodemailer = require('nodemailer');
const chokidar = require('chokidar');
const path = require('path');
const fs = require('fs');

require('dotenv').config();

// console.log("emailService.js file loaded");

// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD
    }
});

// Function to send email with details and attachment
function sendEmailWithDetails(filePath, meetingDetails) {
    console.log("Meeting Details in Email Service:", meetingDetails);
    const emailBody = `
    <h1>Meeting Details</h1>
    <p>Here are the details of the meeting:</p>
    <ul>
        <li>Meeting Topic: ${meetingDetails.topic}</li>
        <li>Meeting Start Time: ${meetingDetails.startTime}</li>
        <li>Meeting End Time: ${meetingDetails.endTime}</li>
        <li>Meeting Duration: ${meetingDetails.duration}</li>
    </ul>
    <p>Attached you will find the detailed participants report.</p>
    `;

    sendEmailWithAttachment(filePath, emailBody);
}

function sendEmailWithAttachment(filePath, emailBody) {
    fs.access(filePath, fs.constants.F_OK | fs.constants.R_OK, (err) => {
        if (err) {
            console.error('File does not exist or is not readable:', err);
            return;
        }

        const emailOptions = {
            from: process.env.EMAIL_USER,
            to: ['sediqi.ah@gmail.com'],
            subject: 'New CSV Report Available',
            html: emailBody,
            attachments: [
                { path: filePath }
            ]
        };

        transporter.sendMail(emailOptions, function (error, info) {
            if (error) {
                console.error('Email could not be sent:', error);
            } else {
                console.log('Email sent:', info.response);
            }
        });
    });
}

// Watch the csvProcessed folder and send email when a new file is added
const watcher = chokidar.watch(path.join(__dirname, '../csvProcessed'), {
    ignored: /(^|[\/\\])\../, // ignore dotfiles
    persistent: true
});

watcher.on('add', filePath => {
    console.log(`File ${filePath} has been added.`);
});

module.exports = { sendEmailWithAttachment, sendEmailWithDetails };