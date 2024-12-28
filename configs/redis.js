const { createClient } = require("redis");

const redisClient = createClient({
  url: "redis://redis:6379",
});

redisClient.on("error", (err) => console.log("Redis Client Error", err));
redisClient.on("ready", () => console.log("Redis Client Ready"));

module.exports = redisClient;

// const { createClient } = require("redis");
// require("dotenv").config();

// class RedisClient {
//   constructor() {
//     this.client = null;
//     this.isConnected = false;
//   }

//   async getClient() {
//     if (this.client && this.isConnected) {
//       return this.client;
//     }

//     this.client = createClient({
//       url: process.env.REDIS_URL || "redis://redis:6379",
//       socket: {
//         reconnectStrategy: (retries) => {
//           if (retries > 10) {
//             return new Error("Redis connection failed");
//           }
//           return Math.min(retries * 100, 3000);
//         },
//       },
//       legacyMode: false,
//     });

//     this.client.on("error", (err) => {
//       console.error("Redis Client Error:", err);
//       this.isConnected = false;
//     });

//     this.client.on("ready", () => {
//       console.log("Redis Client Ready");
//       this.isConnected = true;
//     });

//     try {
//       await this.client.connect();
//       this.isConnected = true;
//       return this.client;
//     } catch (error) {
//       console.error("Redis connection error:", error);
//       throw error;
//     }
//   }

//   async disconnect() {
//     if (this.client) {
//       await this.client.quit();
//       this.isConnected = false;
//     }
//   }
// }

// module.exports = new RedisClient();
