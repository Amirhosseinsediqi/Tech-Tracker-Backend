const mongoose = require('mongoose');
const User = require('./models/User');

// MongoDB connection configuration
const mongoOptions = {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    family: 4,
    keepAlive: true,
    keepAliveInitialDelay: 300000
};

// Connect to MongoDB
mongoose.connect("mongodb://mongodb:27017/meetings", mongoOptions)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

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
    } catch (error) {
        console.error('[ERROR] Error verifying data:', error);
    }
}

// Main test function
async function runStressTest() {
    console.log('[START] Starting stress test...');
    
    const batchTimestamps = [];
    
    // Create data in batches
    for (let i = 0; i < 10; i++) {
        console.log(`[PROGRESS] Running batch ${i + 1}/10`);
        const timestamp = await createTestData(100); // Create 100 documents per batch
        if (timestamp) batchTimestamps.push(timestamp);
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second between batches
    }

    // Verify data every minute for 5 minutes
    console.log('[VERIFY] Starting verification phase...');
    for (let i = 0; i < 5; i++) {
        console.log(`[VERIFY] Verification round ${i + 1}/5`);
        for (const timestamp of batchTimestamps) {
            await verifyData(timestamp);
        }
        await new Promise(resolve => setTimeout(resolve, 60000)); // Wait 1 minute
    }

    console.log('[END] Stress test completed');
    process.exit(0);
}

// Handle process termination
process.on('SIGTERM', () => {
    console.log('[SHUTDOWN] Received SIGTERM - Cleaning up...');
    mongoose.connection.close(() => {
        console.log('[SHUTDOWN] MongoDB connection closed');
        process.exit(0);
    });
});

// Run the test
runStressTest();
