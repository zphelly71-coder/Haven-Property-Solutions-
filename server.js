
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
app.post(
  "/api/admin/cloudinary-signature",
  requireAdmin,
  (req, res) => {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(503).json({
        status: "error",
        message: "Cloudinary is not configured"
      });
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder = "haven-property-solutions";

    const signature = crypto
      .createHash("sha1")
      .update(`folder=${folder}&timestamp=${timestamp}${apiSecret}`)
      .digest("hex");

    res.json({
      cloudName,
      apiKey,
      timestamp,
      folder,
      signature
    });
  }
);
app.post("/api/enquiries", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const { ObjectId } = require("mongodb");
    const body = req.body || {};

    const propertyId =
      typeof body.propertyId === "string"
        ? body.propertyId.trim()
        : "";

    const name =
      typeof body.name === "string" ? body.name.trim() : "";

    const email =
      typeof body.email === "string"
        ? body.email.trim().toLowerCase()
        : "";

    const phone =
      typeof body.phone === "string" ? body.phone.trim() : "";

    const message =
      typeof body.message === "string"
        ? body.message.trim()
        : "";

    if (!ObjectId.isValid(propertyId)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid property selection"
      });
    }

    if (!name || name.length > 100) {
      return res.status(400).json({
        status: "error",
        message: "Enter your name (maximum 100 characters)"
      });
    }

    if (
      email.length > 254 ||
      (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    ) {
      return res.status(400).json({
        status: "error",
        message: "Enter a valid email address"
      });
    }

    if (
      phone.length > 30 ||
      (phone && !/^[+()\d\s.-]{6,30}$/.test(phone))
    ) {
      return res.status(400).json({
        status: "error",
        message: "Enter a valid phone number"
      });
    }

    if (!email && !phone) {
      return res.status(400).json({
        status: "error",
        message: "Provide an email address or phone number"
      });
    }

    if (!message || message.length > 2000) {
      return res.status(400).json({
        status: "error",
        message: "Enter your enquiry (maximum 2000 characters)"
      });
    }

    const property = await db.collection("properties").findOne({
      _id: new ObjectId(propertyId),
      status: "published"
    });

    if (!property) {
      return res.status(404).json({
        status: "error",
        message: "Property not found or no longer available"
      });
    }

    await db.collection("enquiries").insertOne({
      propertyId: property._id,
      propertyTitle: property.title,
      propertyLocation: property.location,
      name,
      email,
      phone,
      message,
      status: "new",
      createdAt: new Date()
    });
const notificationUrl = process.env.ENQUIRY_NOTIFICATION_URL;
const notificationSecret =
  process.env.ENQUIRY_NOTIFICATION_SECRET;

if (notificationUrl && notificationSecret) {
  try {
    const notificationResponse = await fetch(notificationUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        secret: notificationSecret,
        name,
        email,
        phone,
        propertyTitle: property.title,
        propertyLocation: property.location,
        message
      }),
      signal: AbortSignal.timeout(10000)
    });

    const notificationResult =
      await notificationResponse.json().catch(() => ({}));

    if (
      !notificationResponse.ok ||
      notificationResult.status !== "ok"
    ) {
      console.error(
        "Email notification was not confirmed:",
        notificationResult.message || notificationResponse.status
      );
    }
  } catch (notificationError) {
    console.error(
      "Email notification failed:",
      notificationError.message
    );
  }
} else {
  console.error("Email notification environment variables are missing.");
}
    return res.status(201).json({
      status: "ok",
      message: "Your enquiry was submitted successfully"
    });
  } catch (error) {
    console.error("Customer enquiry submission failed:", error.message);

    return res.status(500).json({
      status: "error",
      message: "Unable to submit your enquiry. Please try again."
    });
  }
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
            createdAt: 1,
            status: 1,
            listingType: 1,
            
            listingPurpose: 1,
            nightlyRate: 1,
            maxGuests: 1,
            minimumNights: 1,
            checkInTime: 1,
            checkOutTime: 1

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
    "listingPurpose",
    "bedrooms",
    "bathrooms",
    "images",
    "status",
    "landSize",
    "landUnit",
    "landUse",
    "titleDeed",
    "nightlyRate",
    "maxGuests",
    "minimumNights",
    "checkInTime",
    "checkOutTime"
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
    "listingPurpose",
    "bedrooms",
    "bathrooms",
    "images",
    "status",
    "landSize",
    "landUnit",
    "landUse",
    "titleDeed",
    "nightlyRate",
    "maxGuests",
    "minimumNights",
    "checkInTime",
    "checkOutTime"
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
app.patch("/api/admin/enquiries/:id", requireAdmin, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const { ObjectId } = require("mongodb");
    const id = req.params.id;
    const newStatus = req.body?.status;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid enquiry ID"
      });
    }

    if (!["new", "contacted", "closed"].includes(newStatus)) {
      return res.status(400).json({
        status: "error",
        message: "Status must be new, contacted, or closed"
      });
    }

    const result = await db.collection("enquiries").updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: newStatus,
          updatedAt: new Date()
        }
      }
    );

    if (!result.matchedCount) {
      return res.status(404).json({
        status: "error",
        message: "Enquiry not found"
      });
    }

    res.json({
      status: "ok",
      message: "Enquiry status updated"
    });
  } catch (error) {
    console.error("Enquiry status update failed:", error.message);

    res.status(500).json({
      status: "error",
      message: "Unable to update enquiry status"
    });
  }
});
app.get("/api/admin/enquiries", requireAdmin, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const enquiries = await db.collection("enquiries")
      .find(
        {},
        {
          projection: {
            propertyId: 1,
            propertyTitle: 1,
            propertyLocation: 1,
            name: 1,
            email: 1,
            phone: 1,
            message: 1,
            status: 1,
            createdAt: 1
          }
        }
      )
      .sort({ createdAt: -1 })
      .limit(100)
      .toArray();

    res.json({
      status: "ok",
      count: enquiries.length,
      enquiries
    });
  } catch (error) {
    console.error("Admin enquiry list failed:", error.message);

    res.status(500).json({
      status: "error",
      message: "Unable to load customer enquiries"
    });
  }
});
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
      "title",
      "description",
      "location",
      "price",
      "pricePeriod",
      "propertyType",
      "listingPurpose",
      "bedrooms",
      "bathrooms",
      "images",
      "status",
      "landSize",
      "landUnit",
      "landUse",
      "titleDeed",
      "nightlyRate",
      "maxGuests",
      "minimumNights",
      "checkInTime",
      "checkOutTime"
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
console.log("MongoDB driver version:", require("mongodb/package.json").version);
console.log("Starting secure MongoDB connection...");
await client.connect();

console.log("MongoDB Atlas connection established.");

  db = client.db(DB_NAME);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Haven API listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error);
  console.error("Underlying cause:", error.cause);
  process.exit(1);
});
