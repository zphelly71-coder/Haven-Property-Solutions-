
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME =
  process.env.MONGODB_DB || "haven_property_solutions";

app.use(cors());
app.use(express.json());

let db;
let mongoClient;
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

    if (!["new", "contacted", "closed", "converted"].includes(newStatus)) {
  return res.status(400).json({
    status: "error",
    message: "Status must be new, contacted, closed, or converted"
  });
}

    const now = new Date();

const update = {
  $set: {
    status: newStatus,
    updatedAt: now
  }
};

if (newStatus === "converted") {
  update.$set.convertedAt = now;
} else {
  update.$unset = { convertedAt: "" };
}

const result = await db.collection("enquiries").updateOne(
  { _id: new ObjectId(id) },
  update
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
app.get("/api/admin/reports/monthly", requireAdmin, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const nairobiParts = Object.fromEntries(
      new Intl.DateTimeFormat("en-US", {
        timeZone: "Africa/Nairobi",
        year: "numeric",
        month: "2-digit"
      }).formatToParts(new Date()).map(part => [
        part.type,
        part.value
      ])
    );

    const year = Number(nairobiParts.year);
    const month = Number(nairobiParts.month) - 1;

    const months = Array.from({ length: 12 }, (_, index) =>
      new Date(Date.UTC(year, month - 11 + index, 1))
        .toISOString()
        .slice(0, 7)
    );

    const startDate = new Date(
      Date.UTC(year, month - 11, 1) - 3 * 60 * 60 * 1000
    );

    const [enquiryMonths, conversionMonths, popularProperties] =
      await Promise.all([
        db.collection("enquiries").aggregate([
          { $match: { createdAt: { $gte: startDate } } },
          {
            $group: {
              _id: {
                $dateToString: {
                  format: "%Y-%m",
                  date: "$createdAt",
                  timezone: "Africa/Nairobi"
                }
              },
              count: { $sum: 1 }
            }
          }
        ]).toArray(),

        db.collection("enquiries").aggregate([
          {
            $match: {
              status: "converted",
              convertedAt: { $gte: startDate }
            }
          },
          {
            $group: {
              _id: {
                $dateToString: {
                  format: "%Y-%m",
                  date: "$convertedAt",
                  timezone: "Africa/Nairobi"
                }
              },
              count: { $sum: 1 }
            }
          }
        ]).toArray(),

        db.collection("enquiries").aggregate([
          { $match: { createdAt: { $gte: startDate } } },
          {
            $group: {
              _id: "$propertyId",
              title: { $first: "$propertyTitle" },
              location: { $first: "$propertyLocation" },
              enquiries: { $sum: 1 }
            }
          },
          { $sort: { enquiries: -1 } },
          { $limit: 5 }
        ]).toArray()
      ]);

    const enquiryCounts = Object.fromEntries(
      enquiryMonths.map(item => [item._id, item.count])
    );

    const conversionCounts = Object.fromEntries(
      conversionMonths.map(item => [item._id, item.count])
    );

    const monthly = months.map(monthKey => ({
      month: monthKey,
      enquiries: enquiryCounts[monthKey] || 0,
      conversions: conversionCounts[monthKey] || 0
    }));

    res.json({
      status: "ok",
      period: "Last 12 months",
      monthly,
      popularProperties: popularProperties.map(item => ({
        title: item.title || "Untitled property",
        location: item.location || "Location not recorded",
        enquiries: item.enquiries
      }))
    });
  } catch (error) {
    console.error("Monthly report failed:", error.message);

    res.status(500).json({
      status: "error",
      message: "Unable to generate monthly business report"
    });
  }
});

app.get("/api/admin/reports/financial", requireAdmin, async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const [deals, expenses] = await Promise.all([
      db.collection("financial_deals").find({}).toArray(),
      db.collection("business_expenses").find({}).toArray()
    ]);

   
const totals = {
  deals: deals.length,
  commissionsEarned: 0,
  commissionsReceived: 0,
  commissionOutstanding: 0,
  resaleRevenue: 0,
  resaleReceipts: 0,
  resaleOutstanding: 0,
  purchaseCosts: 0,
  purchasePayments: 0,
  purchaseOutstanding: 0,
  directDealExpenses: 0,
  resaleProfit: 0,
  businessExpenses: 0
};


    for (const deal of deals) {
      const amount = Number(deal.transactionAmount) || 0;
      const commission = Number(deal.commissionEarned) || 0;
      const purchaseCost = Number(deal.purchaseCost) || 0;
      const directExpenses = Number(deal.directExpenses) || 0;
     
const legacyPaymentReceived =
  Number(deal.paymentReceived) || 0;

const commissionReceived =
  (Number(deal.commissionReceivedTotal) || 0) +
  (deal.transactionType !== "resale"
    ? legacyPaymentReceived
    : 0);

const resaleReceived =
  (Number(deal.resaleReceivedTotal) || 0) +
  (deal.transactionType === "resale"
    ? legacyPaymentReceived
    : 0);

      const purchasePaid =
        Number(deal.purchasePaidTotal) || 0;

      if (deal.transactionType === "resale") {
        totals.resaleRevenue += amount;
        totals.resaleReceipts += resaleReceived;
        totals.resaleOutstanding += Math.max(
  0,
  amount - resaleReceived
);
        totals.purchaseCosts += purchaseCost;
        totals.purchasePayments += purchasePaid;
        totals.purchaseOutstanding += Math.max(
  0,
  purchaseCost - purchasePaid
);
        totals.directDealExpenses += directExpenses;
        totals.resaleProfit += amount - purchaseCost - directExpenses;
     
} else {
  totals.commissionsEarned += commission;
  totals.commissionsReceived += commissionReceived;
  totals.commissionOutstanding += Math.max(
    0,
    commission - commissionReceived
  );
}

    }

    for (const expense of expenses) {
      totals.businessExpenses += Number(expense.amount) || 0;
    }

    totals.estimatedNetProfit =
      totals.resaleProfit +
      totals.commissionsEarned -
      totals.businessExpenses;
    totals.totalOutstanding =
  totals.commissionOutstanding +
  totals.resaleOutstanding;

    res.json({
      status: "ok",
      currency: "KES",
      totals
    });
  } catch (error) {
    console.error("Financial report failed:", error.message);
    res.status(500).json({
      status: "error",
      message: "Unable to generate financial report"
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
const totalEnquiries = await db.collection("enquiries")
  .countDocuments({});

const statusGroups = await db.collection("enquiries")
  .aggregate([
    {
      $group: {
        _id: { $ifNull: ["$status", "new"] },
        count: { $sum: 1 }
      }
    }
  ])
  .toArray();

const summary = {
  total: totalEnquiries,
  new: 0,
  contacted: 0,
  closed: 0,
  converted: 0
};

for (const group of statusGroups) {
  if (["new", "contacted", "closed", "converted"].includes(group._id)) {
    summary[group._id] = group.count;
  }
}
    res.json({
  status: "ok",
  count: enquiries.length,
  enquiries,
  summary
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

function validateMoney(value, fieldName) {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < 0
  ) {
    return `${fieldName} must be a non-negative number`;
  }

  return null;
}

app.get(
  "/api/admin/financial-deals",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const deals = await db
        .collection("financial_deals")
        .find({})
        .sort({ transactionDate: -1 })
        .limit(500)
        .toArray();

      res.json({
        status: "ok",
        count: deals.length,
        deals
      });
    } catch (error) {
      console.error("Financial deals load failed:", error.message);

      res.status(500).json({
        status: "error",
        message: "Unable to load financial deals"
      });
    }
  }
);

app.get(
  "/api/admin/financial-test-cleanup-preview",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const allowedIds = [
        "6ad3812ea062c70b970d829e",
        "6ad38306a062c70b970d82a0",
        "6ad38a93a062c70b970d82a3",
        "6ad38368a062c70b970d82a1"
      ].map(id => new ObjectId(id));

      const deals = await db
        .collection("financial_deals")
        .find({ _id: { $in: allowedIds } })
        .project({
          propertyTitle: 1,
          transactionType: 1,
          transactionAmount: 1,
          commissionEarned: 1,
          purchaseCost: 1,
          notes: 1
        })
        .toArray();

      const payments = await db
        .collection("financial_payments")
        .find({ dealId: { $in: allowedIds } })
        .project({
          dealId: 1,
          purpose: 1,
          direction: 1,
          amount: 1,
          notes: 1
        })
        .toArray();

      res.json({
        status: "ok",
        previewOnly: true,
        deals,
        payments,
        dealCount: deals.length,
        paymentCount: payments.length
      });
    } catch (error) {
      console.error("Financial test cleanup preview failed:", error.message);
      res.status(500).json({
        status: "error",
        message: "Unable to preview test records"
      });
    }
  }
);

app.get(
  "/api/admin/financial-test-cleanup-diagnostic",
  requireAdmin,
  (req, res) => {
    res.json({
      status: "ok",
      diagnosticOnly: true,
      message: "Diagnostic route is reachable"
    });
  }
);

app.post(
  "/api/admin/financial-test-cleanup",
  requireAdmin,
  async (req, res) => {
    if (!db || !mongoClient) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const approvedDeals = [
      {
        id: "6ad3812ea062c70b970d829e",
        title: "TEST - Overpayment Safety Check",
        type: "sale"
      },
      {
        id: "6ad38306a062c70b970d82a0",
        title: "TEST - Resale Payment Safety",
        type: "resale"
      },
      {
        id: "6ad38368a062c70b970d82a1",
        title: "TEST - Resale Payment Safety",
        type: "sale"
      },
      {
        id: "6ad38a93a062c70b970d82a3",
        title: "TEST - Resale Purchase Safety Corrected",
        type: "resale"
      }
    ];

    const approvedPayments = [
      {
        id: "6ad38185a062c70b970d829f",
        dealId: "6ad3812ea062c70b970d829e",
        purpose: "commission",
        direction: "received",
        amount: 60
      },
      {
        id: "6ad383e7a062c70b970d82a2",
        dealId: "6ad38306a062c70b970d82a0",
        purpose: "resale_receipt",
        direction: "received",
        amount: 600
      },
      {
        id: "6ad38b1ba062c70b970d82a4",
        dealId: "6ad38a93a062c70b970d82a3",
        purpose: "purchase_payment",
        direction: "paid",
        amount: 250
      }
    ];

    const session = mongoClient.startSession();

    try {
      let deletedDeals = 0;
      let deletedPayments = 0;
      let safetyCheckFailed = false;

      await session.withTransaction(async () => {
        safetyCheckFailed = false;
        deletedDeals = 0;
        deletedPayments = 0;

        const dealIds = approvedDeals.map(
          item => new ObjectId(item.id)
        );
        const paymentIds = approvedPayments.map(
          item => new ObjectId(item.id)
        );

        const dealsCollection = db.collection("financial_deals");
        const paymentsCollection = db.collection("financial_payments");

        const deals = await dealsCollection.find(
          { _id: { $in: dealIds } },
          { session }
        ).toArray();

        const payments = await paymentsCollection.find(
          { _id: { $in: paymentIds } },
          { session }
        ).toArray();

        const dealsMatch =
          deals.length === approvedDeals.length &&
          approvedDeals.every(expected =>
            deals.some(actual =>
              actual._id.toString() === expected.id &&
              actual.propertyTitle === expected.title &&
              actual.transactionType === expected.type
            )
          );

        const paymentsMatch =
          payments.length === approvedPayments.length &&
          approvedPayments.every(expected =>
            payments.some(actual =>
              actual._id.toString() === expected.id &&
              actual.dealId.toString() === expected.dealId &&
              actual.purpose === expected.purpose &&
              actual.direction === expected.direction &&
              actual.amount === expected.amount
            )
          );

        if (!dealsMatch || !paymentsMatch) {
          safetyCheckFailed = true;
          return;
        }

        const paymentResult = await paymentsCollection.deleteMany(
          { _id: { $in: paymentIds } },
          { session }
        );

        const dealResult = await dealsCollection.deleteMany(
          { _id: { $in: dealIds } },
          { session }
        );

        deletedPayments = paymentResult.deletedCount;
        deletedDeals = dealResult.deletedCount;

        if (
          deletedPayments !== approvedPayments.length ||
          deletedDeals !== approvedDeals.length
        ) {
          throw new Error("Cleanup counts did not match the approved records");
        }
      });

      if (safetyCheckFailed) {
        return res.status(409).json({
          status: "error",
          message: "Safety check failed. No records were deleted."
        });
      }

      return res.json({
        status: "ok",
        message: "Approved test records cleaned up",
        deletedDeals,
        deletedPayments
      });
    } catch (error) {
      console.error("Financial test cleanup failed:", error.message);

      return res.status(500).json({
        status: "error",
        message: "Cleanup failed. Check the database before retrying."
      });
    } finally {
      await session.endSession();
    }
  }
);

app.post(
  "/api/admin/financial-deals",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const body = req.body || {};
      const allowedTypes = ["sale", "rental", "resale"];

      if (
        typeof body.propertyTitle !== "string" ||
        !body.propertyTitle.trim() ||
        body.propertyTitle.trim().length > 150
      ) {
        return res.status(400).json({
          status: "error",
          message: "A valid property title is required"
        });
      }

      if (!allowedTypes.includes(body.transactionType)) {
        return res.status(400).json({
          status: "error",
          message: "Transaction type must be sale, rental, or resale"
        });
      }

      for (const field of [
        "transactionAmount",
        "commissionEarned",
        "purchaseCost",
        "directExpenses",
        "paymentReceived"
      ]) {
        const value = body[field] ?? 0;
        const error = validateMoney(value, field);

        if (error) {
          return res.status(400).json({
            status: "error",
            message: error
          });
        }
      }

      const transactionDate = new Date(body.transactionDate);

      if (
        typeof body.transactionDate !== "string" ||
        !body.transactionDate ||
        Number.isNaN(transactionDate.getTime())
      ) {
        return res.status(400).json({
          status: "error",
          message: "A valid transaction date is required"
        });
      }

     
const deal = {
  propertyTitle: body.propertyTitle.trim(),
  transactionType: body.transactionType,
  transactionDate,
  transactionAmount: body.transactionAmount ?? 0,
  commissionEarned: body.commissionEarned ?? 0,
  purchaseCost: body.purchaseCost ?? 0,
  directExpenses: body.directExpenses ?? 0,
  paymentReceived: body.paymentReceived ?? 0,
  commissionReceivedTotal: 0,
  resaleReceivedTotal: 0,
  purchasePaidTotal: 0,
  notes: typeof body.notes === "string"
    ? body.notes.trim().slice(0, 1000)
    : "",
  createdAt: new Date(),
  updatedAt: new Date()
};

      
const expectedPayment =
  deal.transactionType === "resale"
    ? deal.transactionAmount
    : deal.commissionEarned;

deal.outstandingAmount = Math.max(
  0,
  expectedPayment - deal.paymentReceived
);


      const result = await db
        .collection("financial_deals")
        .insertOne(deal);

      res.status(201).json({
        status: "ok",
        message: "Financial deal saved",
        id: result.insertedId
      });
    } catch (error) {
      console.error("Financial deal save failed:", error.message);

      res.status(500).json({
        status: "error",
        message: "Unable to save financial deal"
      });
    }
  }
);

app.get(
  "/api/admin/business-expenses",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const expenses = await db
        .collection("business_expenses")
        .find({})
        .sort({ expenseDate: -1 })
        .limit(500)
        .toArray();

      res.json({
        status: "ok",
        count: expenses.length,
        expenses
      });
    } catch (error) {
      console.error("Business expenses load failed:", error.message);

      res.status(500).json({
        status: "error",
        message: "Unable to load business expenses"
      });
    }
  }
);

app.post(
  "/api/admin/business-expenses",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const body = req.body || {};
      const category = body.category;
      const description =
        typeof body.description === "string"
          ? body.description.trim()
          : "";
      const amount = body.amount;
      const expenseDate = new Date(body.expenseDate);

      const allowedCategories = [
        "marketing",
        "transport",
        "repairs",
        "office",
        "other"
      ];

      if (!allowedCategories.includes(category)) {
        return res.status(400).json({
          status: "error",
          message: "Select a valid expense category"
        });
      }

      if (!description || description.length > 300) {
        return res.status(400).json({
          status: "error",
          message: "Enter a description (maximum 300 characters)"
        });
      }

      const amountError = validateMoney(amount, "Amount");

      if (amountError || amount <= 0) {
        return res.status(400).json({
          status: "error",
          message: amountError || "Amount must be greater than zero"
        });
      }

      if (
        typeof body.expenseDate !== "string" ||
        !body.expenseDate ||
        Number.isNaN(expenseDate.getTime())
      ) {
        return res.status(400).json({
          status: "error",
          message: "Enter a valid expense date"
        });
      }

      const expense = {
        category,
        description,
        amount,
        expenseDate,
        currency: "KES",
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const result = await db
        .collection("business_expenses")
        .insertOne(expense);

      res.status(201).json({
        status: "ok",
        message: "Business expense saved",
        id: result.insertedId
      });
    } catch (error) {
      console.error("Business expense save failed:", error.message);

      res.status(500).json({
        status: "error",
        message: "Unable to save business expense"
      });
    }
  }
);

app.post(
  "/api/admin/financial-deals/:dealId/payments",
  requireAdmin,
  async (req, res) => {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const { dealId } = req.params;
    const body = req.body || {};

    if (!ObjectId.isValid(dealId)) {
      return res.status(400).json({
        status: "error",
        message: "Invalid property deal ID"
      });
    }

    if (!["received", "paid"].includes(body.direction)) {
      return res.status(400).json({
        status: "error",
        message: "Direction must be received or paid"
      });
    }

    if (
      typeof body.amount !== "number" ||
      !Number.isFinite(body.amount) ||
      body.amount <= 0
    ) {
      return res.status(400).json({
        status: "error",
        message: "Payment amount must be greater than zero"
      });
    }

    if (
      typeof body.paymentDate !== "string" ||
      !body.paymentDate ||
      Number.isNaN(new Date(body.paymentDate).getTime())
    ) {
      return res.status(400).json({
        status: "error",
        message: "A valid payment date is required"
      });
    }

    const allowedPurposes = [
      "commission",
      "resale_receipt",
      "purchase_payment"
    ];

    if (!allowedPurposes.includes(body.purpose)) {
      return res.status(400).json({
        status: "error",
        message:
          "Purpose must be commission, resale_receipt, or purchase_payment"
      });
    }

    const session = mongoClient.startSession();
    let balanceExceeded = false;
    let dealMissing = false;
    let invalidPurposeForDeal = false;
    let insertedPaymentId;

    try {
      await session.withTransaction(async () => {
        balanceExceeded = false;
        dealMissing = false;
        invalidPurposeForDeal = false;
        insertedPaymentId = undefined;

        const deals = db.collection("financial_deals");
        const deal = await deals.findOne(
          { _id: new ObjectId(dealId) },
          { session }
        );

        if (!deal) {
          dealMissing = true;
          return;
        }

        let allowedTotal;
        let totalField;
        let legacyPaymentReceived = 0;

        if (body.purpose === "commission") {
          if (
            !["sale", "rental"].includes(deal.transactionType) ||
            body.direction !== "received"
          ) {
            invalidPurposeForDeal = true;
            return;
          }
          allowedTotal = deal.commissionEarned || 0;
          totalField = "commissionReceivedTotal";
        } else if (body.purpose === "resale_receipt") {
          if (
            deal.transactionType !== "resale" ||
            body.direction !== "received"
          ) {
            invalidPurposeForDeal = true;
            return;
          }
          allowedTotal = deal.transactionAmount || 0;
          totalField = "resaleReceivedTotal";
        } else {
          if (
            deal.transactionType !== "resale" ||
            body.direction !== "paid"
          ) {
            invalidPurposeForDeal = true;
            return;
          }
          allowedTotal = deal.purchaseCost || 0;
          totalField = "purchasePaidTotal";
        }
                if (
          body.purpose === "commission" ||
          body.purpose === "resale_receipt"
        ) {
          legacyPaymentReceived =
            Number(deal.paymentReceived) || 0;
        }

        // The conditional update atomically reserves room for this payment.
        // The transaction keeps the total and payment-ledger entry in sync.
        const updateResult = await deals.updateOne(
          {
            _id: new ObjectId(dealId),
            $expr: {
              $lte: [
                {
                  $add: [
  { $ifNull: [`$${totalField}`, 0] },
  legacyPaymentReceived,
  body.amount
]
                },
                allowedTotal
              ]
            }
          },
          {
            $inc: { [totalField]: body.amount },
            $set: { updatedAt: new Date() }
          },
          { session }
        );

        if (!updateResult.matchedCount) {
          balanceExceeded = true;
          return;
        }

        const payment = {
          dealId: new ObjectId(dealId),
          direction: body.direction,
          purpose: body.purpose,
          amount: body.amount,
          paymentDate: new Date(body.paymentDate),
          notes: typeof body.notes === "string"
            ? body.notes.trim().slice(0, 500)
            : "",
          createdAt: new Date()
        };

        const result = await db
          .collection("financial_payments")
          .insertOne(payment, { session });
        insertedPaymentId = result.insertedId;
      });

      if (dealMissing) {
        return res.status(404).json({
          status: "error",
          message: "Property deal not found"
        });
      }

      if (invalidPurposeForDeal) {
        return res.status(400).json({
          status: "error",
          message: "Payment purpose or direction does not match this deal type"
        });
      }

      if (balanceExceeded) {
        return res.status(400).json({
          status: "error",
          message: "This payment exceeds the remaining balance for this purpose."
        });
      }

      return res.status(201).json({
        status: "ok",
        message: "Payment recorded successfully",
        id: insertedPaymentId
      });
    } catch (error) {
      console.error("Payment recording failed:", error.message);
      return res.status(500).json({
        status: "error",
        message: "Unable to record payment"
      });
    } finally {
      await session.endSession();
    }
  }
);

app.get(
  "/api/admin/financial-deals/:dealId/payments",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const { dealId } = req.params;

      if (!ObjectId.isValid(dealId)) {
        return res.status(400).json({
          status: "error",
          message: "Invalid property deal ID"
        });
      }

      const payments = await db
        .collection("financial_payments")
        .find({
          dealId: new ObjectId(dealId)
        })
        .sort({ paymentDate: -1, createdAt: -1 })
        .toArray();

      res.json({
        status: "ok",
        count: payments.length,
        payments
      });
    } catch (error) {
      console.error("Payment history load failed:", error.message);

      res.status(500).json({
        status: "error",
        message: "Unable to load payment history"
      });
    }
  }
);

async function startServer() {
  if (!MONGODB_URI) {
    throw new Error("MONGODB_URI environment variable is missing.");
  }

  mongoClient = new MongoClient(MONGODB_URI, {
  serverSelectionTimeoutMS: 15000,
  connectTimeoutMS: 15000, 
  family: 4
});

console.log("Connecting to MongoDB Atlas...");
console.log("MongoDB driver version:", require("mongodb/package.json").version);
console.log("Starting secure MongoDB connection...");
await mongoClient.connect();

console.log("MongoDB Atlas connection established.");

  db = mongoClient.db(DB_NAME);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Haven API listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error);
  console.error("Underlying cause:", error.cause);
  process.exit(1);
});
