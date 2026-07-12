import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import Razorpay from "razorpay";
import crypto from "crypto";
import fs from "fs";

dotenv.config();

const DB_FILE = path.join(process.cwd(), "applications-db.json");

// Default initial seeded applications
const INITIAL_APPLICATIONS = [
  {
    id: "app-1",
    fullName: "Amit Sharma",
    email: "amit.sharma@gmail.com",
    mobile: "9876543211",
    city: "Delhi",
    targetExam: "SSC CGL 2024 Tier I Online Form",
    status: "Submitted to Board",
    submittedAt: "2026-06-15 14:32",
    paymentMethod: "UPI (GPay)",
    price: 100,
    orderId: "ORD-8273641",
    adminNotes: "Fee processed. Application successfully submitted to board server."
  },
  {
    id: "app-2",
    fullName: "Rohit Kumar",
    email: "rohit.k@gmail.com",
    mobile: "9812345670",
    city: "Patna",
    targetExam: "UP Police Constable Exam 2024",
    status: "Pending Verification",
    submittedAt: "2026-07-07 11:20",
    paymentMethod: "Razorpay (Gateway)",
    price: 100,
    orderId: "ORD-9102834",
    adminNotes: "Signature verified. Needs board upload."
  },
  {
    id: "app-3",
    fullName: "Neha Sharma",
    email: "neha.s@yahoo.com",
    mobile: "9445566778",
    city: "Lucknow",
    targetExam: "UPSSSC Junior Assistant Form 2026",
    status: "Submitted to Board",
    submittedAt: "2026-07-08 09:15",
    paymentMethod: "Razorpay (Gateway)",
    price: 100,
    orderId: "ORD-7312384",
    adminNotes: "Uploaded & confirmation slip sent to candidate."
  }
];

function readApplications(): any[] {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify(INITIAL_APPLICATIONS, null, 2), "utf-8");
      return INITIAL_APPLICATIONS;
    }
    const data = fs.readFileSync(DB_FILE, "utf-8");
    return JSON.parse(data || "[]");
  } catch (error) {
    console.error("Error reading applications db file:", error);
    return [];
  }
}

function writeApplications(apps: any[]) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(apps, null, 2), "utf-8");
  } catch (error) {
    console.error("Error writing applications db file:", error);
  }
}

// Lazy initialize Razorpay client to prevent crashing if keys are not set
let razorpayInstance: any = null;
function getRazorpay() {
  if (!razorpayInstance) {
    const keyId = process.env.RAZORPAY_KEY_ID;
    const keySecret = process.env.RAZORPAY_KEY_SECRET;
    if (!keyId || !keySecret) {
      throw new Error("Razorpay credentials (RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET) are missing");
    }
    razorpayInstance = new Razorpay({
      key_id: keyId,
      key_secret: keySecret,
    });
  }
  return razorpayInstance;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // API Route: Create Razorpay Order
  app.post("/api/create-order", async (req, res) => {
    try {
      const { amount, currency = "INR", receipt } = req.body;
      
      // Validation: amount must be >= 100 paise (Rs 1)
      if (!amount || typeof amount !== "number" || amount < 100) {
        return res.status(400).json({ 
          error: "Invalid amount. Minimum amount is 100 paise (₹1)." 
        });
      }

      const razorpay = getRazorpay();
      const options = {
        amount: Math.round(amount), // paise
        currency,
        receipt: receipt || `receipt_${Date.now()}`,
      };

      const order = await razorpay.orders.create(options);
      return res.json({
        order_id: order.id,
        amount: order.amount,
        currency: order.currency,
        key_id: process.env.RAZORPAY_KEY_ID
      });
    } catch (error: any) {
      console.error("Error creating Razorpay order:", error);
      return res.status(500).json({ 
        error: error.message || "Failed to create Razorpay order" 
      });
    }
  });

  // API Route: Verify Payment Signature
  app.post("/api/verify-payment", async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

      if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        return res.status(400).json({ 
          error: "Missing payment fields: razorpay_order_id, razorpay_payment_id, razorpay_signature are required." 
        });
      }

      const secret = process.env.RAZORPAY_KEY_SECRET;
      if (!secret) {
        return res.status(500).json({ error: "Razorpay Key Secret is not configured on the server." });
      }

      // Hashing algorithm: HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET)
      const hmac = crypto.createHmac("sha256", secret);
      hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
      const generatedSignature = hmac.digest("hex");

      if (generatedSignature === razorpay_signature) {
        return res.json({ 
          success: true, 
          message: "Payment signature verified successfully." 
        });
      } else {
        return res.status(400).json({ 
          success: false, 
          error: "Payment signature verification failed. Invalid transaction." 
        });
      }
    } catch (error: any) {
      console.error("Error verifying payment:", error);
      return res.status(500).json({ 
        error: error.message || "Failed to verify signature" 
      });
    }
  });

  // Middleware to verify the team passkey sent in headers
  const verifyAdmin = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const passkey = req.headers["x-admin-passkey"];
    const expectedPasskey = process.env.ADMIN_PASSKEY || "sarkariteam2026";
    if (passkey !== expectedPasskey) {
      return res.status(401).json({ error: "Unauthorized access: Invalid team passkey." });
    }
    next();
  };

  // Public API Route: Track status of applications by mobile, email, or order ID
  app.post("/api/track-applications", (req, res) => {
    try {
      const { searchVal } = req.body;
      if (!searchVal) {
        return res.status(400).json({ error: "Please provide a valid Mobile Number, Email Address, or Order ID." });
      }
      const val = searchVal.trim().toLowerCase();
      const applications = readApplications();
      const results = applications.filter(app => 
        (app.mobile && app.mobile.toLowerCase() === val) ||
        (app.email && app.email.toLowerCase() === val) ||
        (app.orderId && app.orderId.toLowerCase() === val) ||
        (app.id && app.id.toLowerCase() === val)
      );
      return res.json(results);
    } catch (error: any) {
      console.error("Error tracking applications:", error);
      return res.status(500).json({ error: "Failed to query applications." });
    }
  });

  // Secure API Route: Get all applications for Team Tracker
  app.get("/api/admin/applications", verifyAdmin, (req, res) => {
    try {
      const applications = readApplications();
      return res.json(applications);
    } catch (error: any) {
      console.error("Error fetching applications securely:", error);
      return res.status(500).json({ error: "Failed to load applications list." });
    }
  });

  // Secure API Route: Update application status and admin notes from dashboard
  app.post("/api/admin/update-status", verifyAdmin, (req, res) => {
    try {
      const { id, status, notes } = req.body;
      if (!id) {
        return res.status(400).json({ error: "Record identifier (id/orderId) is required." });
      }

      const applications = readApplications();
      // Search by either standard ID or order ID for maximum resilience
      const existingIndex = applications.findIndex(app => app.id === id || app.orderId === id);

      if (existingIndex > -1) {
        if (status !== undefined) {
          applications[existingIndex].status = status;
          // Synchronize paymentStatus for back-compat if requested
          applications[existingIndex].paymentStatus = status;
        }
        if (notes !== undefined) {
          applications[existingIndex].adminNotes = notes;
        }

        writeApplications(applications);
        return res.json({ 
          success: true, 
          message: "Candidate record updated successfully.", 
          application: applications[existingIndex] 
        });
      } else {
        return res.status(404).json({ error: "No records found matching that ID." });
      }
    } catch (error: any) {
      console.error("Error updating application status securely:", error);
      return res.status(500).json({ error: error.message || "Failed to update status securely." });
    }
  });

  // API Route: Save or insert new application record (public/customer facing on submission)
  app.post("/api/save-application", (req, res) => {
    try {
      const appData = req.body;
      if (!appData.fullName || !appData.mobile) {
        return res.status(400).json({ error: "Full Name and Mobile number are required." });
      }

      const applications = readApplications();
      const existingIndex = applications.findIndex(app => app.orderId === appData.orderId);

      const newApp = {
        id: appData.id || `app-${Date.now()}`,
        fullName: appData.fullName,
        email: appData.email,
        mobile: appData.mobile,
        city: appData.city || "Not Specified",
        targetExam: appData.targetExam,
        status: appData.status || "Pending Verification",
        submittedAt: appData.submittedAt || new Date().toISOString().replace("T", " ").substring(0, 16),
        paymentMethod: appData.paymentMethod || "Razorpay Gateway",
        price: appData.price || 100,
        orderId: appData.orderId,
        paymentId: appData.paymentId || "",
        adminNotes: appData.adminNotes || "Awaiting submission checks."
      };

      if (existingIndex > -1) {
        applications[existingIndex] = { ...applications[existingIndex], ...newApp };
      } else {
        applications.unshift(newApp);
      }

      writeApplications(applications);
      return res.json({ success: true, application: newApp });
    } catch (error: any) {
      console.error("Error saving application:", error);
      return res.status(500).json({ error: error.message || "Failed to save application." });
    }
  });

  // Vite middleware for development or Static Server for production
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error("Failed to start server:", err);
});
