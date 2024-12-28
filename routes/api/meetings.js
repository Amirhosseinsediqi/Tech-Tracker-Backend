const express = require('express');
const axios = require('axios');
const qs = require('query-string');
const fs = require('fs');
const path = require('path');
const { Parser } = require('json2csv');
const moment = require('moment');
const csv = require('csv-parser');


const errorHandler = require('../../utils/errorHandler');
const { ZOOM_API_BASE_URL } = require('../../constants');
// const { getToken, setToken } = require('../../utils/token');

const downloadJsonDir = '/app/downloads'; // Directory for downloads JSON files
const savedCsvDir = '/app/savedCsv'; // Directory for save CSV files
const processedCsvDir = '/app/csvProcessed'; // Directory for processed CSVs


const router = express.Router();


// Ensure the processedCsv directory exists
[downloadJsonDir, savedCsvDir, processedCsvDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});



router.get('/:meetingId', async (req, res) => {
    const { headerConfig, params } = req;
    const { meetingId } = params;

    try {
        const request = await axios.get(`${ZOOM_API_BASE_URL}/meetings/${meetingId}`, headerConfig);
        return res.json(request.data);
    } catch (err) {
        return errorHandler(err, res, `Error fetching meeting: ${meetingId}`);
    }
});


router.post('/:userId', async (req, res) => {
    const { headerConfig, params, body } = req;
    const { userId } = params;

    try {
        const request = await axios.post(`${ZOOM_API_BASE_URL}/users/${userId}/meetings`, body, headerConfig);
        return res.json(request.data);
    } catch (err) {
        return errorHandler(err, res, `Error creating meeting for user: ${userId}`);
    }
});


router.patch('/:meetingId', async (req, res) => {
    const { headerConfig, params, body } = req;
    const { meetingId } = params;

    try {
        const request = await axios.patch(`${ZOOM_API_BASE_URL}/meetings/${meetingId}`, body, headerConfig);
        return res.json(request.data);
    } catch (err) {
        return errorHandler(err, res, `Error updating meeting: ${meetingId}`);
    }
});

router.delete('/:meetingId', async (req, res) => {
    const { headerConfig, params } = req;
    const { meetingId } = params;

    try {
        const request = await axios.delete(`${ZOOM_API_BASE_URL}/meetings/${meetingId}`, headerConfig);
        return res.json(request.data);
    } catch (err) {
        return errorHandler(err, res, `Error deleting meeting: ${meetingId}`);
    }
});


// Utility function to read CSV file
function readCsvFile(filePath) {
    return new Promise((resolve, reject) => {
        const results = [];
        fs.createReadStream(filePath)
            .pipe(csv({
                mapHeaders: ({ header }) => header.toLowerCase().trim()
            }))
            .on('data', (data) => results.push(data))
            .on('end', () => resolve(results))
            .on('error', (error) => reject(error));
    });
}

// Function to process Zoom participation from a CSV file
async function processZoomParticipation(file_path, output_directory) {
    const rows = await readCsvFile(file_path);
    const joinLateCutoff = 10; // minutes after meeting start to consider as late
    const participationCutoff = 90; // percent of the meeting duration to be considered as present

    // Assuming the first participant's join time is the start of the meeting
    const firstJoinTime = moment(rows[0]['join_time'], moment.ISO_8601);

    let processedResults = rows.map(row => {
        const joinTime = moment(row['join_time'], moment.ISO_8601);
        const leaveTime = moment(row['leave_time'], moment.ISO_8601);
        const durationMinutes = Math.round(moment.duration(leaveTime.diff(joinTime)).asMinutes());
        const joinLateMinutes = Math.round(moment.duration(joinTime.diff(firstJoinTime)).asMinutes());

        // Determine if the participant was late and if they participated enough
        const wasLate = joinLateMinutes > joinLateCutoff;
        const didParticipateEnough = durationMinutes >= participationCutoff;
        const status = (!wasLate && didParticipateEnough) ? 'Present' : 'Absent';

        return {
            ...row,
            'Status': status
        };
    });

    // Convert processed results to CSV
    const processedFilePath = path.join(output_directory, `processed_${path.basename(file_path)}`);
    const fields = ['id', 'name', 'user_email', 'join_time', 'leave_time', 'duration', 'Status'];
    const json2csvParser = new Parser({ fields });
    const csv = json2csvParser.parse(processedResults);

    fs.writeFileSync(processedFilePath, csv, 'utf8');
    console.log(`Processed file saved to ${processedFilePath}`);
}


router.get('/:meetingId/report/participants', async (req, res) => {
    console.log(process.cwd());
    const { headerConfig, params, query } = req;
    const { meetingId } = params;
    const { next_page_token } = query;

    try {
        const request = await axios.get(`${ZOOM_API_BASE_URL}/report/meetings/${meetingId}/participants?${qs.stringify({ next_page_token })}`, headerConfig);

        const directory = path.join(__dirname, downloadJsonDir);

        const filePath = path.join(downloadJsonDir, `${meetingId}_participants.json`);
        const csvFilePath = path.join(savedCsvDir, `${meetingId}_participants.csv`);

        
        // Write the JSON file
        fs.writeFileSync(filePath, JSON.stringify(request.data, null, 2), 'utf8');

        // Process participants data for CSV conversion, ensuring the keys match the source data structure
        const participants = request.data.participants.map(participant => {
            return {
                ...participant,
                duration: Math.round(participant.duration / 60) // Adjusted to ensure whole number representation
            };
        });

        // Define fields for CSV, ensuring they match the participant object keys
        const fields = ['id', 'name', 'user_email', 'join_time', 'leave_time', 'duration']; // Use 'duration' as adjusted
        const json2csvParser = new Parser({ fields });
        const csv = json2csvParser.parse(participants);

        // Write the CSV file
        fs.writeFileSync(csvFilePath, csv, 'utf8');

        // Integrate delay calculation logic
        await processZoomParticipation(csvFilePath, processedCsvDir);

        res.send({
            message: 'Files saved successfully',
            jsonFilePath: filePath,
            csvFilePath,
            processedCsvPath: path.join(processedCsvDir, `processed_${meetingId}_participants.csv`)
        });

    } catch (err) {
        console.error('Error:', err);
        errorHandler(err, res, `Error fetching participants for meeting: ${meetingId}`);
    }
});

router.delete('/:meetingId/recordings', async (req, res) => {
    const { headerConfig, params, query } = req;
    const { meetingId } = params;
    const { action } = query;

    try {
        const request = await axios.delete(`${ZOOM_API_BASE_URL}/meetings/${meetingId}/recordings?${qs.stringify({ action })}`, headerConfig);
        return res.json(request.data);
    } catch (err) {
        return errorHandler(err, res, `Error deleting recordings for meeting: ${meetingId}`);
    }
});




module.exports = router;
