require('dotenv').config();
const mongoose = require('mongoose');
const fs = require('fs');

const MONGODB_URI = 'mongodb://admin:password123@localhost:27017/meetings?authSource=admin';

// Keep track of previous counts
let previousCounts = {};

async function monitorCollections() {
    try {
        await mongoose.connect(MONGODB_URI);

        const timestamp = new Date().toISOString();
        console.log('\n--- Monitoring Check at:', timestamp, '---');

        // Get all collections
        const collections = await mongoose.connection.db.collections();

        const stats = {};
        for (const collection of collections) {
            const collStats = await mongoose.connection.db.command({ collStats: collection.collectionName });
            const currentCount = await collection.countDocuments();
            
            // Check for significant changes in document count
            if (previousCounts[collection.collectionName] !== undefined) {
                const difference = currentCount - previousCounts[collection.collectionName];
                if (Math.abs(difference) > 0) {
                    const alert = `⚠️ ${timestamp}: ${collection.collectionName} changed by ${difference} documents (${previousCounts[collection.collectionName]} → ${currentCount})`;
                    console.log('\x1b[31m%s\x1b[0m', alert); // Red color
                    fs.appendFileSync('alerts.log', alert + '\n');
                    
                    // If it's the users collection and documents were lost, get more details
                    if (collection.collectionName === 'users' && difference < 0) {
                        const profileCollection = mongoose.connection.db.collection('system.profile');
                        const recentOps = await profileCollection
                            .find({ 
                                ns: 'meetings.users',
                                ts: { 
                                    $gte: new Date(Date.now() - 5 * 60 * 1000) // Last 5 minutes
                                }
                            })
                            .sort({ ts: -1 })
                            .toArray();
                            
                        fs.appendFileSync('alerts.log', 
                            `\nRecent operations on users collection:\n${JSON.stringify(recentOps, null, 2)}\n\n`);
                            
                        // Get a sample of remaining documents
                        const remainingDocs = await collection
                            .find({})
                            .limit(5)
                            .sort({ _id: -1 })
                            .toArray();
                            
                        fs.appendFileSync('alerts.log', 
                            `\nSample of remaining documents:\n${JSON.stringify(remainingDocs, null, 2)}\n\n`);
                    }
                }
            }
            
            previousCounts[collection.collectionName] = currentCount;

            stats[collection.collectionName] = {
                count: currentCount,
                size: collStats.size,
                storageSize: collStats.storageSize,
                avgObjSize: collStats.avgObjSize,
                lastModified: new Date()
            };

            // Sample a recent document from each collection
            const sample = await collection.findOne({}, { sort: { _id: -1 } });
            if (sample) {
                stats[collection.collectionName].lastDocument = {
                    id: sample._id,
                    createdAt: sample.createdAt || 'N/A'
                };
            }
        }

        // Log to file with timestamp
        const logEntry = `${timestamp}: ${JSON.stringify(stats, null, 2)}\n`;
        fs.appendFileSync('data-monitor.log', logEntry);

        console.log('Collection Stats:', JSON.stringify(stats, null, 2));

        // Check for any recent delete operations
        const profileCollection = mongoose.connection.db.collection('system.profile');
        const recentDeletes = await profileCollection
            .find({ op: 'remove' })
            .sort({ ts: -1 })
            .limit(5)
            .toArray();

        if (recentDeletes.length > 0) {
            console.log('\n⚠️ Recent Delete Operations Found:', recentDeletes);
            fs.appendFileSync('delete-operations.log', 
                `${timestamp} - Delete operations found:\n${JSON.stringify(recentDeletes, null, 2)}\n\n`);
        }

    } catch (error) {
        console.error('Error:', error);
        fs.appendFileSync('monitor-errors.log', 
            `${timestamp}: ${error.message}\n${error.stack}\n\n`);
    } finally {
        await mongoose.connection.close();
    }
}

// Run immediately and then every 30 seconds
monitorCollections();
setInterval(monitorCollections, 30 * 1000); // Check every 30 seconds

process.on('SIGINT', async () => {
    console.log('Monitoring stopped');
    process.exit();
});