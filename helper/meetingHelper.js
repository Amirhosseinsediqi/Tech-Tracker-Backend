// const { Meeting } = require('../index');

// async function getMeetingDetailsFromDB(id) {
//     try {
//       console.log("Meeting ID to fetch: ", id);
//       const meetingDetails = await Meeting.findOne({ id: Number(id) }).exec();
//       console.log("from meetinghelper: ", meetingDetails);
  
//       if (!meetingDetails) {
//         throw new Error(`Meeting with ID ${id} not found`);
//       }
//       return meetingDetails;
//     } catch (error) {
//       console.error(`Error fetching meeting details: ${error.message}`);
//       throw error;
//     }
// }
  
// module.exports = { getMeetingDetailsFromDB };
