
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient } = require("mongodb");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME =
  process.env.MONGODB_DB || "haven_property_solutions";

app.use(cors());
app.use(express.json());

let db;
const adminSessions = new Map();
const SESSION_DURATION = 2 * 60 * 60 * 1000;

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) {
    return false;
  }

  return crypto.timingSafeEqual(first, second);
}

function requireAdmin(req, res, next) {
  const authorization = req.headers.authorization || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  const expiresAt = adminSessions.get(token);

  if (!token || !expiresAt || expiresAt < Date.now()) {
    adminSessions.delete(token);
    return res.status(401).json({
      status: "error",
      message: "Admin login required"
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    message: "Haven Property Solutions API",
    status: "running"
  });
});
app.post("/api/admin/login", (req, res) => {
  const password = req.body?.password;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminPassword) {
    return res.status(503).json({
      status: "error",
      message: "Admin login is not configured"
    });
  }

  if (
    typeof password !== "string" ||
    !safeCompare(password, adminPassword)
  ) {
    return res.status(401).json({
      status: "error",
      message: "Invalid admin password"
    });
  }

  const token = crypto.randomBytes(32).toString("hex");

  adminSessions.set(
    token,
    Date.now() + SESSION_DURATION
  );

  return res.json({
    status: "ok",
    token,
    expiresIn: SESSION_DURATION
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    database: db ? "connected" : "not connected"
  });
});

app.get("/api/properties", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const properties = await db.collection("properties")
      .find(
        { status: "published" },
        {
          projection: {
            title: 1,
            description: 1,
            location: 1,
            price: 1,
            pricePeriod: 1,
            propertyType: 1,
            bedrooms: 1,
            bathrooms: 1,
            images: 1,
            createdAt: 1
          }
        }
      )
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      status: "ok",
      count: properties.length,
      properties
    });
  } catch (error) {
    console.error("Failed to load properties:", error.message);
    res.status(500).json({
      status: "error",
      message: "Unable to load properties"
    });
  }
});


function validateProperty(data) {
  const allowed = [
    "title",
    "description",
    "location",
    "price",
    "pricePeriod",
    "propertyType",
    "bedrooms",
    "bathrooms",
    "images",
    "status"
  ];

  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return "Invalid property data";
  }

  if (
    typeof data.title !== "string" ||
    !data.title.trim() ||
    data.title.length > 150
  ) {
    return "Title is required (maximum 150 characters)";
  }

  if (
    typeof data.description !== "string" ||
    data.description.length > 5000
  ) {
    return "Description is required and must be under 5000 characters";
  }

  if (
    typeof data.location !== "string" ||
    !data.location.trim() ||
    data.location.length > 200
  ) {
    return "A valid location is required";
  }

  if (
    typeof data.price !== "number" ||
    !Number.isFinite(data.price) ||
    data.price < 0
  ) {
    return "Price must be a valid non-negative number";
  }

  if (
    data.pricePeriod !== undefined &&
    !["month", "week", "day", "night", "once"].includes(data.pricePeriod)
  ) {
    return "Invalid price period";
  }

  if (
    data.status !== undefined &&
    !["draft", "published"].includes(data.status)
  ) {
    return "Status must be draft or published";
  }

  for (const field of ["bedrooms", "bathrooms"]) {
    if (
      data[field] !== undefined &&
      (!Number.isInteger(data[field]) || data[field] < 0 || data[field] > 100)
    ) {
      return "Bedrooms and bathrooms must be whole numbers from 0 to 100";
    }
  }

  if (
    data.images !== undefined &&
    (!Array.isArray(data.images) ||
      data.images.length > 10 ||
      !data.images.every(
        image => typeof image === "string" && image.length <= 2000
      ))
  ) {
    return "Images must be a list of up to 10 image URLs";
  }

  return null;
}

function cleanProperty(data) {
  const fields = [
    "title",
    "description",
    "location",
    "price",
    "pricePeriod",
    "propertyType",
    "bedrooms",
    "bathrooms",
    "images",
    "status"
  ];

  const result = {};

  for (const field of fields) {
    if (data[field] !== undefined) {
      result[field] = data[field];
    }
  }

  if (typeof result.title === "string") result.title = result.title.trim();
  if (typeof result.location === "string") result.location = result.location.trim();

  return result;
}

app.get("/api/admin/properties", requireAdmin, async (req, res) => {
  try {
    const properties = await db.collection("properties")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      status: "ok",
      count: properties.length,
      properties
    });
  } catch (error) {
    console.error("Admin property list failed:", error.message);
    res.status(500).json({
      status: "error",
      message: "Unable to load admin properties"
    });
  }
});

app.post("/api/properties", requireAdmin, async (req, res) => {
  try {
    const error = validateProperty(req.body);

    if (error) {
      return res.status(400).json({ status: "error", message: error });
    }

    const property = {
      ...cleanProperty(req.body),
      status: req.body.status || "published",
      createdAt: new Date()
    };

    const result = await db.collection("properties").insertOne(property);

    res.status(201).json({
      status: "ok",
      id: result.insertedId
    });
  } catch (error) {
    console.error("Create property failed:", error.message);
    res.status(500).json({ status: "error", message: "Unable to create property" });
  }
});


app.patch("/api/properties/:id", requireAdmin, async (req, res) => {
  try {
    const { ObjectId } = require("mongodb");

    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid property ID"
      });
    }

    const changes = cleanProperty(req.body);

    if (Object.keys(changes).length === 0) {
      return res.status(400).json({
        status: "error",
        message: "No changes supplied"
      });
    }

    const allowed = [
      "title", "description", "location", "price",
      "pricePeriod", "propertyType", "bedrooms",
      "bathrooms", "images", "status"
    ];

    for (const key of Object.keys(changes)) {
      if (!allowed.includes(key)) {
        return res.status(400).json({
          status: "error",
          message: "Unsupported property field"
        });
      }
    }

    const current = await db.collection("properties").findOne({
      _id: new ObjectId(req.params.id)
    });

    if (!current) {
      return res.status(404).json({
        status: "error",
        message: "Property not found"
      });
    }

    const error = validateProperty({
      ...current,
      ...changes
    });

    if (error) {
      return res.status(400).json({
        status: "error",
        message: error
      });
    }

    await db.collection("properties").updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: changes }
    );

    res.json({
      status: "ok",
      message: "Property updated"
    });
  } catch (error) {
    console.error("Update property failed:", error.message);
    res.status(500).json({
      status: "error",
      message: "Unable to update property"
    });
  }
});


app.delete("/api/properties/:id", requireAdmin, async (req, res) => {
  try {
    const { ObjectId } = require("mongodb");

    if (!ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ status: "error", message: "Invalid property ID" });
    }

    const result = await db.collection("properties").deleteOne({
      _id: new ObjectId(req.params.id)
    });

    if (!result.deletedCount) {
      return res.status(404).json({ status: "error", message: "Property not found" });
    }

    res.json({ status: "ok", message: "Property deleted" });
  } catch (error) {
    console.error("Delete property failed:", error.message);
    res.status(500).json({ status: "error", message: "Unable to delete property" });
  }
});

async function startServer() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI environment variable is missing.");
  }

  const client = new MongoClient(MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000, 
  family: 4
});

console.log("Connecting to MongoDB Atlas...");

await client.connect();

console.log("MongoDB Atlas connection established.");

  db = client.db(DB_NAME);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Haven API listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
