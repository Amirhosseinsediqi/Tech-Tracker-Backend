require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

// MongoDB connection configuration
const mongoOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 30000,
    heartbeatFrequencyMS: 10000,
    authSource: 'admin'
};

// Connect to MongoDB with retry mechanism
const connectToMongoDB = async (retryCount = 0, maxRetries = 5) => {
    try {
        const mongoUri = process.env.MONGODB_URI || 'mongodb://admin:password123@mongodb:27017/meetings?authSource=admin';
        await mongoose.connect(mongoUri, mongoOptions);
        console.log('[MONITOR] Connected to MongoDB successfully');
        return true;
    } catch (error) {
        console.error('[ERROR] MongoDB connection error:', error);
        if (retryCount < maxRetries) {
            const delay = Math.min((retryCount + 1) * 5000, 30000);
            console.log(`[RETRY] Retrying connection in ${delay/1000} seconds... (Attempt ${retryCount + 1}/${maxRetries})`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return connectToMongoDB(retryCount + 1, maxRetries);
        }
        return false;
    }
};

// Monitor connection events
mongoose.connection.on('error', err => {
    console.error('[MONITOR] MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.error('[MONITOR] MongoDB disconnected');
});

mongoose.connection.on('connected', () => {
    console.log('[MONITOR] MongoDB connected');
});

mongoose.connection.on('reconnected', () => {
    console.log('[MONITOR] MongoDB reconnected');
});

// Function to create test data
async function createTestData(batchSize) {
    try {
        const startTime = Date.now();
        const promises = [];
        const timestamp = Date.now();

        for (let i = 0; i < batchSize; i++) {
            const testUser = new User({
                email: `test${timestamp}_${i}@test.com`,
                username: `testuser_${timestamp}_${i}`,
                createdAt: new Date()
            });
            promises.push(testUser.save());
        }

        await Promise.all(promises);
        console.log(`[DATA] Batch of ${batchSize} documents created in ${Date.now() - startTime}ms`);
        return timestamp;
    } catch (error) {
        console.error('[ERROR] Error creating test data:', error);
        return null;
    }
}

// Function to verify data persistence
async function verifyData(timestamp) {
    try {
        const totalCount = await User.countDocuments();
        const batchCount = await User.countDocuments({
            email: new RegExp(`test${timestamp}.*@test.com`)
        });
        console.log(`[VERIFY] Total documents: ${totalCount}, Latest batch documents: ${batchCount}`);
        
        if (batchCount < 100) {
            console.error(`[ALERT] Data loss detected! Expected 100 documents for timestamp ${timestamp}, found ${batchCount}`);
        }
        return batchCount;
    } catch (error) {
        console.error('[ERROR] Error verifying data:', error);
        return 0;
    }
}

// Main test function
async function runStressTest() {
    console.log('[START] Starting stress test...');
    
    // First ensure MongoDB is connected
    const connected = await connectToMongoDB();
    if (!connected) {
        console.error('[FATAL] Could not connect to MongoDB after multiple retries');
        process.exit(1);
    }
    
    const batchTimestamps = [];
    let totalDocuments = 0;
    
    // Create data in batches
    for (let i = 0; i < 10; i++) {
        console.log(`[PROGRESS] Running batch ${i + 1}/10`);
        const timestamp = await createTestData(100); // Create 100 documents per batch
        if (timestamp) {
            batchTimestamps.push(timestamp);
            totalDocuments += 100;
        }
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second between batches
    }

    console.log(`[INFO] Created ${totalDocuments} total documents`);

    // Verify data every minute for 5 minutes
    console.log('[VERIFY] Starting verification phase...');
    let verificationsPassed = 0;
    
    for (let i = 0; i < 5; i++) {
        console.log(`[VERIFY] Verification round ${i + 1}/5`);
        let roundPassed = true;
        
        for (const timestamp of batchTimestamps) {
            const count = await verifyData(timestamp);
            if (count < 100) {
                roundPassed = false;
            }
        }
        
        if (roundPassed) {
            verificationsPassed++;
        }
        
        await new Promise(resolve => setTimeout(resolve, 60000)); // Wait 1 minute
    }

    console.log(`[SUMMARY] Stress test completed:`);
    console.log(`- Total documents created: ${totalDocuments}`);
    console.log(`- Verification rounds passed: ${verificationsPassed}/5`);
    
    if (verificationsPassed === 5) {
        console.log('[SUCCESS] All verification rounds passed! No data loss detected.');
    } else {
        console.log('[WARNING] Some verification rounds failed. Possible data loss detected.');
    }

    await mongoose.connection.close();
    process.exit(verificationsPassed === 5 ? 0 : 1);
}

// Handle process termination
process.on('SIGTERM', async () => {
    console.log('[SHUTDOWN] Received SIGTERM - Cleaning up...');
    await mongoose.connection.close();
    process.exit(0);
});

// Run the test
runStressTest().catch(error => {
    console.error('[FATAL] Unhandled error:', error);
    process.exit(1);
});
