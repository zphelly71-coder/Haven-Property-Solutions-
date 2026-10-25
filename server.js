
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME =
  process.env.MONGODB_DB || "haven_property_solutions";
const MPESA_CONSUMER_KEY = process.env.MPESA_CONSUMER_KEY;
const MPESA_CONSUMER_SECRET = process.env.MPESA_CONSUMER_SECRET;
const MPESA_PASSKEY = process.env.MPESA_PASSKEY;
const MPESA_CALLBACK_URL = process.env.MPESA_CALLBACK_URL;
const MPESA_SHORTCODE = process.env.MPESA_SHORTCODE || "174379";
const MPESA_ENVIRONMENT = process.env.MPESA_ENVIRONMENT || "sandbox";

const MPESA_BASE_URL =
  MPESA_ENVIRONMENT === "production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";
app.use(cors({
  origin: "https://zphelly71-coder.github.io",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 204
}));
app.use(express.json());

let db;
let mongoClient;
const adminSessions = new Map();
const SESSION_DURATION = 2 * 60 * 60 * 1000;
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
function cleanupLoginAttempts(now = Date.now()) {
  for (const [clientKey, attempt] of loginAttempts) {
    const expired =
      attempt.lockedUntil <= now &&
      now - attempt.windowStartedAt >= LOGIN_WINDOW_MS;

    if (expired) {
      loginAttempts.delete(clientKey);
    }
  }
}
function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) {
    return false;
  }

  return crypto.timingSafeEqual(first, second);
}

async function getMpesaAccessToken() {
  if (!MPESA_CONSUMER_KEY || !MPESA_CONSUMER_SECRET) {
    throw new Error("Daraja credentials are not configured");
  }

  const credentials = Buffer.from(
    `${MPESA_CONSUMER_KEY}:${MPESA_CONSUMER_SECRET}`
  ).toString("base64");

  const response = await fetch(
    `${MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
    {
      method: "GET",
      headers: {
        Authorization: `Basic ${credentials}`
      },
      signal: AbortSignal.timeout(15000)
    }
  );

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    throw new Error("Daraja authentication failed");
  }

  return data.access_token;
}

function getMpesaTimestamp() {
  // East Africa Time (UTC+3)
  return new Date(Date.now() + 3 * 60 * 60 * 1000)
    .toISOString()
    .replace(/[-T:.Z]/g, "")
    .slice(0, 14);
}

async function initiateMpesaStkPush({
  phoneNumber,
  amount,
  accountReference
}) {
  if (!MPESA_PASSKEY || !MPESA_SHORTCODE || !MPESA_CALLBACK_URL) {
    throw new Error("Daraja STK Push configuration is incomplete");
  }

  if (!Number.isSafeInteger(amount) || amount < 1) {
    throw new Error("Amount must be a positive whole number");
  }

 if (!/^254[17]\d{8}$/.test(phoneNumber)) {
    throw new Error("Phone number must use format 2547XXXXXXXX");
  }

  if (!MPESA_CALLBACK_URL.startsWith("https://")) {
    throw new Error("An HTTPS callback URL is required");
  }

  const timestamp = getMpesaTimestamp();

  const password = Buffer.from(
    `${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`
  ).toString("base64");

  const accessToken = await getMpesaAccessToken();

  const response = await fetch(
    `${MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        BusinessShortCode: MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: amount,
        PartyA: phoneNumber,
        PartyB: MPESA_SHORTCODE,
        PhoneNumber: phoneNumber,
        CallBackURL: MPESA_CALLBACK_URL,
        AccountReference: accountReference,
        TransactionDesc: "Property pay"
      }),
      signal: AbortSignal.timeout(20000)
    }
  );

  const data = await response.json();

    if (
    !response.ok ||
    String(data.ResponseCode) !== "0" ||
    !data.MerchantRequestID ||
    !data.CheckoutRequestID
  ) {
    console.error("Daraja STK request failed:", {
      status: response.status,
      errorCode: data.errorCode
    });

    throw new Error("Daraja did not accept the STK Push request");
  }

  return data;
}

async function queryMpesaStkStatus(checkoutRequestId) {
  if (!checkoutRequestId || !MPESA_PASSKEY || !MPESA_SHORTCODE) {
    throw new Error("STK Query configuration is incomplete");
  }

  const timestamp = getMpesaTimestamp();

  const password = Buffer.from(
    `${MPESA_SHORTCODE}${MPESA_PASSKEY}${timestamp}`
  ).toString("base64");

  const accessToken = await getMpesaAccessToken();

  const response = await fetch(
    `${MPESA_BASE_URL}/mpesa/stkpushquery/v1/query`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        BusinessShortCode: MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        CheckoutRequestID: checkoutRequestId
      }),
      signal: AbortSignal.timeout(15000)
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("Daraja STK Query HTTP error:", response.status);
    throw new Error("Unable to verify STK transaction with Daraja");
  }

  return data;
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

app.post(
  "/api/admin/mpesa/stk-push",
  requireAdmin,
  async (req, res) => {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const { dealId, phoneNumber } = req.body || {};
    const amount = Number(req.body?.amount);

    if (!ObjectId.isValid(dealId || "")) {
      return res.status(400).json({
        status: "error",
        message: "A valid property deal ID is required"
      });
    }

    if (
      !Number.isSafeInteger(amount) ||
      amount < 1 ||
      amount > 150000
    ) {
      return res.status(400).json({
        status: "error",
        message: "Enter a valid whole-number amount"
      });
    }

    if (
      typeof phoneNumber !== "string" ||
      !/^254[17]\d{8}$/.test(phoneNumber)
    ) {
      return res.status(400).json({
        status: "error",
        message: "Use phone format 2547XXXXXXXX or 2541XXXXXXXX"
      });
    }

    if (MPESA_ENVIRONMENT !== "sandbox") {
      return res.status(400).json({
        status: "error",
        message: "This test endpoint is restricted to the sandbox"
      });
    }

    let pendingId;

    try {
      const deals = db.collection("financial_deals");
      const deal = await deals.findOne({
        _id: new ObjectId(dealId)
      });

      if (!deal) {
        return res.status(404).json({
          status: "error",
          message: "Property deal not found"
        });
      }

      if (deal.transactionType !== "resale") {
        return res.status(400).json({
          status: "error",
          message: "Sandbox test requires an existing resale deal"
        });
      }

      const allowedTotal = Number(deal.transactionAmount) || 0;
      const recordedTotal = Number(deal.resaleReceivedTotal) || 0;
      const legacyReceived = Number(deal.paymentReceived) || 0;
      const remaining = allowedTotal - recordedTotal - legacyReceived;

      if (amount > remaining) {
        return res.status(400).json({
          status: "error",
          message: "Amount exceeds the remaining resale balance",
          remaining: Math.max(0, remaining)
        });
      }

      // This record tracks the request only. It is NOT a payment.
      const pending = {
        dealId: new ObjectId(dealId),
        purpose: "resale_receipt",
        direction: "received",
        amount,
        phoneNumber,
        status: "initiating",
        createdAt: new Date(),
        updatedAt: new Date()
      };

      const saved = await db
        .collection("mpesa_stk_requests")
        .insertOne(pending);

      pendingId = saved.insertedId;

      const stk = await initiateMpesaStkPush({
        phoneNumber,
        amount,
        accountReference: `HPS${String(pendingId).slice(-8)}`
      });

      await db.collection("mpesa_stk_requests").updateOne(
        { _id: pendingId, status: "initiating" },
        {
          $set: {
            status: "pending",
            merchantRequestId: stk.MerchantRequestID,
            checkoutRequestId: stk.CheckoutRequestID,
            responseCode: stk.ResponseCode,
            updatedAt: new Date()
          }
        }
      );


      const earlyEvent = await db
        .collection("mpesa_callback_events")
        .findOne({
          checkoutRequestId: String(stk.CheckoutRequestID),
          status: "unmatched"
        });

      if (earlyEvent?.callback?.Body?.stkCallback) {
        const earlyCallback = earlyEvent.callback.Body.stkCallback;

        if (
          String(earlyCallback.CheckoutRequestID) ===
          String(stk.CheckoutRequestID)
        ) {
          const attached = await db
            .collection("mpesa_stk_requests")
            .updateOne(
              {
                _id: pendingId,
                checkoutRequestId: String(stk.CheckoutRequestID),
                status: "pending"
              },
              {
                $set: {
                  status: "verification_required",
                  callbackData: earlyCallback,
                  callbackReceivedAt:
                    earlyEvent.receivedAt || new Date(),
                  updatedAt: new Date()
                }
              }
            );

          if (attached.modifiedCount === 1) {
            await db
              .collection("mpesa_callback_events")
              .updateOne(
                {
                  _id: earlyEvent._id,
                  status: "unmatched"
                },
                {
                  $set: {
                    status: "attached",
                    attachedAt: new Date()
                  }
                }
              );
          }
        }
      }

      return res.status(202).json({
        status: "ok",
        message: "STK Push request accepted; awaiting payment result",
        requestId: pendingId,
        checkoutRequestId: stk.CheckoutRequestID
      });
    } catch (error) {
      console.error("STK Push initiation failed:", error.message);

      if (pendingId) {
        await db.collection("mpesa_stk_requests").updateOne(
          { _id: pendingId, status: "initiating" },
          {
            $set: {
              status: "initiation_error",
              updatedAt: new Date()
            }
          }
        ).catch(() => {});
      }

      return res.status(502).json({
        status: "error",
        message: "Unable to initiate STK Push; check server logs"
      });
    }
  }
);

app.get("/", (req, res) => {
  res.json({
    message: "Haven Property Solutions API",
    status: "running"
  });
});
app.get("/property.html", (req, res) => {
  res.sendFile(path.join(__dirname, "property.html"));
});
app.get("/admin.html", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});
app.post("/api/admin/login", (req, res) => {
  cleanupLoginAttempts();
  const now = Date.now();
const clientKey = req.ip || req.socket.remoteAddress || "unknown";
let attempt = loginAttempts.get(clientKey);

if (attempt && attempt.lockedUntil > now) {
  return res.status(429).json({
    status: "error",
    message: "Too many failed login attempts. Try again in 15 minutes."
  });
}

if (!attempt || now - attempt.windowStartedAt >= LOGIN_WINDOW_MS) {
  attempt = {
    count: 0,
    windowStartedAt: now,
    lockedUntil: 0
  };
  loginAttempts.set(clientKey, attempt);
}
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
  attempt.count += 1;

  if (attempt.count >= MAX_LOGIN_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
  }

  loginAttempts.set(clientKey, attempt);

  return res.status(401).json({
    status: "error",
    message: "Invalid admin password"
  });
}
  loginAttempts.delete(clientKey);
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
app.post("/api/admin/logout", requireAdmin, (req, res) => {
  const authorization = req.headers.authorization || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  adminSessions.delete(token);

  return res.json({
    status: "ok",
    message: "Logged out successfully"
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

app.post("/api/contact", async (req, res) => {
  try {
    if (!db) {
      return res.status(503).json({
        status: "error",
        message: "Database not connected"
      });
    }

    const body = req.body || {};
    const name =
      typeof body.name === "string" ? body.name.trim() : "";
    const email =
      typeof body.email === "string"
        ? body.email.trim().toLowerCase()
        : "";
    const messageText =
      typeof body.message === "string"
        ? body.message.trim()
        : "";

    if (!name || name.length > 100) {
      return res.status(400).json({
        status: "error",
        message: "Enter your name (maximum 100 characters)"
      });
    }

    if (
      !email ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        status: "error",
        message: "Enter a valid email address"
      });
    }

    if (!messageText || messageText.length > 2000) {
      return res.status(400).json({
        status: "error",
        message: "Enter your message (maximum 2000 characters)"
      });
    }

    await db.collection("enquiries").insertOne({
      type: "general_contact",
      propertyTitle: "General Website Contact",
      propertyLocation: "Website contact form",
      name,
      email,
      phone: "",
      message: messageText,
      status: "new",
      createdAt: new Date()
    });

    return res.status(201).json({
      status: "ok",
      message: "Your message has been submitted successfully."
    });
  } catch (error) {
    console.error("General contact submission failed:", error.message);

    return res.status(500).json({
      status: "error",
      message: "Unable to submit your message. Please try again."
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

        // Land details
        landSize: 1,
        landUnit: 1,
        landUse: 1,
        titleDeed: 1,

        // Rental inventory
        rentalArrangement: 1,
        totalRentalUnits: 1,
        availableRentalUnits: 1,

        // Airbnb / short-stay details
        nightlyRate: 1,
        maxGuests: 1,
        minimumNights: 1,
        checkInTime: 1,
        checkOutTime: 1,
        guestCapacity: 1,
        stayAmenities: 1,
        checkInInfo: 1
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

    // Land details
    "landSize",
    "landUnit",
    "landUse",
    "titleDeed",

    // Rental inventory
    "rentalArrangement",
    "totalRentalUnits",
    "availableRentalUnits",

    // Airbnb / short-stay details
    "nightlyRate",
    "maxGuests",
    "minimumNights",
    "checkInTime",
    "checkOutTime",
    "guestCapacity",
    "stayAmenities",
    "checkInInfo"
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

  // Rental arrangement
  if (
    data.rentalArrangement !== undefined &&
    !["whole", "units", "rooms"].includes(data.rentalArrangement)
  ) {
    return "Rental arrangement must be whole, units, or rooms";
  }

  // Rental inventory and guest capacity
  for (const field of [
    "totalRentalUnits",
    "availableRentalUnits",
    "guestCapacity"
  ]) {
    if (
      data[field] !== undefined &&
      (!Number.isInteger(data[field]) ||
        data[field] < 0 ||
        data[field] > 10000)
    ) {
      return field + " must be a whole number from 0 to 10000";
    }
  }

  if (
    Number.isInteger(data.totalRentalUnits) &&
    Number.isInteger(data.availableRentalUnits) &&
    data.totalRentalUnits > 0 &&
    data.availableRentalUnits > data.totalRentalUnits
  ) {
    return "Available rental units cannot exceed total rental units";
  }

  // Short-stay numeric fields
  for (const field of ["nightlyRate", "maxGuests", "minimumNights"]) {
    if (
      data[field] !== undefined &&
      (typeof data[field] !== "number" ||
        !Number.isFinite(data[field]) ||
        data[field] < (field === "minimumNights" ? 1 : 0) ||
        data[field] > 1000000)
    ) {
      return "Invalid value for " + field;
    }
  }

  // Short-stay text fields
  for (const field of [
    "checkInTime",
    "checkOutTime",
    "stayAmenities",
    "checkInInfo"
  ]) {
    if (
      data[field] !== undefined &&
      (typeof data[field] !== "string" ||
        data[field].length > (field === "stayAmenities" ||
          field === "checkInInfo" ? 2000 : 100))
    ) {
      return "Invalid text value for " + field;
    }
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

    // Land details
    "landSize",
    "landUnit",
    "landUse",
    "titleDeed",

    // Rental inventory
    "rentalArrangement",
    "totalRentalUnits",
    "availableRentalUnits",

    // Airbnb / short-stay details
    "nightlyRate",
    "maxGuests",
    "minimumNights",
    "checkInTime",
    "checkOutTime",
    "guestCapacity",
    "stayAmenities",
    "checkInInfo"
  ];

  const result = {};

  for (const field of fields) {
    if (data[field] !== undefined) {
      result[field] = data[field];
    }
  }

  if (typeof result.title === "string") {
    result.title = result.title.trim();
  }

  if (typeof result.location === "string") {
    result.location = result.location.trim();
  }

  if (typeof result.stayAmenities === "string") {
    result.stayAmenities = result.stayAmenities.trim();
  }

  if (typeof result.checkInInfo === "string") {
    result.checkInInfo = result.checkInInfo.trim();
  }

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
          {
  $match: {
    createdAt: { $gte: startDate },
    propertyId: { $exists: true, $nin: [null, ""] }
  }
},
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

  // Land details
  "landSize",
  "landUnit",
  "landUse",
  "titleDeed",

  // Rental inventory
  "rentalArrangement",
  "totalRentalUnits",
  "availableRentalUnits",

  // Airbnb / short-stay details
  "nightlyRate",
  "maxGuests",
  "minimumNights",
  "checkInTime",
  "checkOutTime",
  "guestCapacity",
  "stayAmenities",
  "checkInInfo"
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


app.post("/api/mpesa/callback", async (req, res) => {
  const callback = req.body?.Body?.stkCallback;

  if (!callback?.CheckoutRequestID) {
    return res.status(400).json({
      ResultCode: 1,
      ResultDesc: "Invalid callback"
    });
  }

  const checkoutId = String(callback.CheckoutRequestID);
  const resultCode = Number(callback.ResultCode);

  try {
    if (!db || !mongoClient) {
      return res.status(503).json({
        ResultCode: 1,
        ResultDesc: "Database unavailable"
      });
    }

    const requests = db.collection("mpesa_stk_requests");

    // Find the request created when the STK prompt was initiated.
    const existingRequest = await requests.findOne({
      checkoutRequestId: checkoutId
    });

    if (!existingRequest) {
      // Retain unmatched callbacks for investigation and recovery.
      await db.collection("mpesa_callback_events").updateOne(
        { checkoutRequestId: checkoutId },
        {
          $setOnInsert: {
            checkoutRequestId: checkoutId,
            callback: req.body,
            status: "unmatched",
            receivedAt: new Date()
          }
        },
        { upsert: true }
      );

      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Callback retained for investigation"
      });
    }

    // Never change a completed payment because of a repeated callback.
    if (existingRequest.status === "completed") {
      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Callback already processed"
      });
    }

    // Failed or cancelled prompts are not financial payments.
    if (resultCode !== 0) {
      await requests.updateOne(
        {
          _id: existingRequest._id,
          status: { $in: ["pending", "verification_required"] }
        },
        {
          $set: {
            status: "failed",
            resultCode: callback.ResultCode,
            resultDescription: String(
              callback.ResultDesc || "Payment unsuccessful"
            ).slice(0, 300),
            callbackReceivedAt: new Date(),
            updatedAt: new Date()
          }
        }
      );

      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Callback processed"
      });
    }

    // Persist the callback BEFORE making the external query.
    // If Daraja is temporarily unavailable, the result is not lost.
    const savedCallback = await requests.updateOne(
      {
        _id: existingRequest._id,
        status: { $in: ["pending", "verification_required"] }
      },
      {
        $set: {
          status: "verification_required",
          callbackData: callback,
          callbackReceivedAt: new Date(),
          updatedAt: new Date()
        }
      }
    );

    if (!savedCallback.matchedCount) {
      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Request already being processed or finalized"
      });
    }

    let queryResult;

    try {
      queryResult = await queryMpesaStkStatus(checkoutId);
    } catch (error) {
      console.error("STK Query unavailable:", error.message);

      // The callback is persisted. Reconciliation must retry this request.
      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Callback saved for reconciliation"
      });
    }

    // Verify that the query response belongs to this checkout request
    // and explicitly reports a successful transaction.
    if (
      String(queryResult.CheckoutRequestID || "") !== checkoutId ||
      String(queryResult.ResponseCode) !== "0" ||
      String(queryResult.ResultCode) !== "0"
    ) {
      console.warn("STK transaction requires reconciliation:", {
        checkoutId,
        queryCheckoutId: queryResult.CheckoutRequestID,
        responseCode: queryResult.ResponseCode,
        resultCode: queryResult.ResultCode
      });

      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Callback saved for reconciliation"
      });
    }

    const items = callback.CallbackMetadata?.Item || [];
    const metadata = {};

    for (const item of items) {
      if (item.Name) metadata[item.Name] = item.Value;
    }

    const receipt = String(metadata.MpesaReceiptNumber || "");
    const callbackAmount = Number(metadata.Amount);
    const callbackPhone = String(metadata.PhoneNumber || "");

    if (
      !receipt ||
      !Number.isSafeInteger(callbackAmount) ||
      callbackAmount < 1 ||
      !callbackPhone
    ) {
      await requests.updateOne(
        {
          _id: existingRequest._id,
          status: "verification_required"
        },
        {
          $set: {
            status: "verification_error",
            updatedAt: new Date()
          }
        }
      );

      return res.status(200).json({
        ResultCode: 0,
        ResultDesc: "Callback requires investigation"
      });
    }

    const session = mongoClient.startSession();

    try {
      await session.withTransaction(async () => {
        const request = await requests.findOne(
          {
            _id: existingRequest._id,
            checkoutRequestId: checkoutId,
            status: "verification_required"
          },
          { session }
        );

        // A repeated callback or concurrent handler cannot record twice.
        if (!request) return;

        if (
          request.purpose !== "resale_receipt" ||
          request.direction !== "received" ||
          request.amount !== callbackAmount ||
          request.phoneNumber !== callbackPhone ||
          (
            request.merchantRequestId &&
            String(callback.MerchantRequestID || "") !==
              String(request.merchantRequestId)
          ) ||
          (
            queryResult.MerchantRequestID &&
            request.merchantRequestId &&
            String(queryResult.MerchantRequestID) !==
              String(request.merchantRequestId)
          )
        ) {
          await requests.updateOne(
            { _id: request._id, status: "verification_required" },
            {
              $set: {
                status: "verification_error",
                updatedAt: new Date()
              }
            },
            { session }
          );
          return;
        }

        const payments = db.collection("financial_payments");

        const duplicate = await payments.findOne(
          { mpesaReceiptNumber: receipt },
          { session }
        );

        if (duplicate) {
          await requests.updateOne(
            { _id: request._id, status: "verification_required" },
            {
              $set: {
                status: "duplicate_receipt",
                updatedAt: new Date()
              }
            },
            { session }
          );
          return;
        }

        const deals = db.collection("financial_deals");
        const deal = await deals.findOne(
          { _id: request.dealId },
          { session }
        );

        if (!deal || deal.transactionType !== "resale") {
          await requests.updateOne(
            { _id: request._id, status: "verification_required" },
            {
              $set: {
                status: "verification_error",
                updatedAt: new Date()
              }
            },
            { session }
          );
          return;
        }

        const allowedTotal = Number(deal.transactionAmount) || 0;
        const legacyReceived = Number(deal.paymentReceived) || 0;

        // Recheck the balance and update it atomically.
        const updateResult = await deals.updateOne(
          {
            _id: request.dealId,
            $expr: {
              $lte: [
                {
                  $add: [
                    { $ifNull: ["$resaleReceivedTotal", 0] },
                    legacyReceived,
                    request.amount
                  ]
                },
                allowedTotal
              ]
            }
          },
          {
            $inc: { resaleReceivedTotal: request.amount },
            $set: { updatedAt: new Date() }
          },
          { session }
        );

        if (!updateResult.matchedCount) {
          await requests.updateOne(
            { _id: request._id, status: "verification_required" },
            {
              $set: {
                status: "balance_exceeded",
                updatedAt: new Date()
              }
            },
            { session }
          );
          return;
        }

        const transactionDate = String(
          metadata.TransactionDate || ""
        );

        let paymentDate = new Date();

        if (/^\d{14}$/.test(transactionDate)) {
          const iso =
            `${transactionDate.slice(0, 4)}-` +
            `${transactionDate.slice(4, 6)}-` +
            `${transactionDate.slice(6, 8)}T` +
            `${transactionDate.slice(8, 10)}:` +
            `${transactionDate.slice(10, 12)}:` +
            `${transactionDate.slice(12, 14)}+03:00`;

          const parsed = new Date(iso);

          if (!Number.isNaN(parsed.getTime())) {
            paymentDate = parsed;
          }
        }

        await payments.insertOne(
          {
            dealId: request.dealId,
            direction: "received",
            purpose: "resale_receipt",
            amount: request.amount,
            paymentDate,
            notes: `M-Pesa receipt ${receipt}`,
            paymentMethod: "mpesa",
            mpesaReceiptNumber: receipt,
            mpesaCheckoutRequestId: checkoutId,
            createdAt: new Date()
          },
          { session }
        );

        await requests.updateOne(
          { _id: request._id, status: "verification_required" },
          {
            $set: {
              status: "completed",
              mpesaReceiptNumber: receipt,
              completedAt: new Date(),
              updatedAt: new Date()
            },
            $unset: { callbackData: "" }
          },
          { session }
        );
      });
    } catch (error) {
      if (
  error.code === 11000 &&
  (
    error.keyPattern?.mpesaReceiptNumber ||
    error.message?.includes("uniq_mpesa_receipt_number")
  )
) {
        // Unique receipt index protects against concurrent duplicate receipts.
        await requests.updateOne(
          {
            _id: existingRequest._id,
            status: "verification_required"
          },
          {
            $set: {
              status: "duplicate_receipt",
              updatedAt: new Date()
            }
          }
        );

        return res.status(200).json({
          ResultCode: 0,
          ResultDesc: "Duplicate receipt retained for investigation"
        });
      }

      throw error;
    } finally {
      await session.endSession();
    }

    return res.status(200).json({
      ResultCode: 0,
      ResultDesc: "Callback processed"
    });
  } catch (error) {
    console.error("M-Pesa callback processing failed:", error.message);

    return res.status(500).json({
      ResultCode: 1,
      ResultDesc: "Callback processing failed"
    });
  }
});

app.get(
  "/api/admin/mpesa/reconciliation",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      const requests = await db
        .collection("mpesa_stk_requests")
        .find({
          status: {
            $in: [
              "verification_required",
              "verification_error",
              "balance_exceeded",
              "duplicate_receipt",
              "initiation_error"
            ]
          }
        })
        .project({
          dealId: 1,
          amount: 1,
          phoneNumber: 1,
          purpose: 1,
          direction: 1,
          status: 1,
          checkoutRequestId: 1,
          merchantRequestId: 1,
          mpesaReceiptNumber: 1,
          resultCode: 1,
          resultDescription: 1,
          createdAt: 1,
          updatedAt: 1,
          callbackReceivedAt: 1
        })
        .sort({ updatedAt: -1 })
        .limit(100)
        .toArray();

      return res.json({
        status: "ok",
        count: requests.length,
        requests
      });
    } catch (error) {
      console.error("M-Pesa reconciliation load failed:", error.message);

      return res.status(500).json({
        status: "error",
        message: "Unable to load reconciliation requests"
      });
    }
  }
);

app.post(
  "/api/admin/mpesa/reconciliation/retry",
  requireAdmin,
  async (req, res) => {
    try {
      if (!db) {
        return res.status(503).json({
          status: "error",
          message: "Database not connected"
        });
      }

      if (!MPESA_CALLBACK_URL) {
        return res.status(503).json({
          status: "error",
          message: "M-Pesa callback URL is not configured"
        });
      }

      // Only retry callbacks already saved for verification.
      const savedRequests = await db
        .collection("mpesa_stk_requests")
        .find({
          status: "verification_required",
          checkoutRequestId: { $type: "string" },
          callbackData: { $exists: true }
        })
        .sort({ updatedAt: 1 })
        .limit(20)
        .project({
          checkoutRequestId: 1,
          callbackData: 1
        })
        .toArray();

      const results = [];

      for (const request of savedRequests) {
        try {
          // Re-submit the saved callback to the existing handler.
          // This does not create a new STK Push.
          const response = await fetch(MPESA_CALLBACK_URL, {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              Body: {
                stkCallback: request.callbackData
              }
            }),
            signal: AbortSignal.timeout(30000)
          });

          const currentRequest = await db
  .collection("mpesa_stk_requests")
  .findOne(
    { _id: request._id },
    {
      projection: {
        status: 1,
        mpesaReceiptNumber: 1
      }
    }
  );

results.push({
  checkoutRequestId: request.checkoutRequestId,
  httpStatus: response.status,
  callbackAccepted: response.ok,
  requestStatus: currentRequest?.status || "not_found",
  completed: currentRequest?.status === "completed"
});
        } catch (error) {
          console.error(
            "M-Pesa reconciliation retry failed:",
            request.checkoutRequestId,
            error.message
          );

          results.push({
            checkoutRequestId: request.checkoutRequestId,
            accepted: false,
            message: "Retry failed; request remains for investigation"
          });
        }
      }

      return res.json({
        status: "ok",
        attempted: results.length,
        results
      });
    } catch (error) {
      console.error(
        "M-Pesa reconciliation retry endpoint failed:",
        error.message
      );

      return res.status(500).json({
        status: "error",
        message: "Unable to retry M-Pesa reconciliation"
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
  
  await db.collection("admin_login_attempts").createIndex(
    { expiresAt: 1 },
    {
      expireAfterSeconds: 0,
      name: "ttl_admin_login_attempts"
    }
  );

  await db.collection("financial_payments").createIndex(
  { mpesaReceiptNumber: 1 },
  {
    unique: true,
    sparse: true,
    name: "uniq_mpesa_receipt_number"
  }
);

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Haven API listening on port ${PORT}`);
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error);
  console.error("Underlying cause:", error.cause);
  process.exit(1);
});
