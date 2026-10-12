
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME =
  process.env.MONGODB_DB || "haven_property_solutions";

app.use(cors());
app.use(express.json());

let db;

app.get("/", (req, res) => {
  res.json({
    message: "Haven Property Solutions API",
    status: "running"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    database: db ? "connected" : "not connected"
  });
});

async function startServer() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI environment variable is missing.");
  }

  const client = new MongoClient(MONGODB_URI);
  await client.connect();

  db = client.db(DB_NAME);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Haven API listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
