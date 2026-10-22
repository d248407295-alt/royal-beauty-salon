import "dotenv/config";
import express from "express";
import Database from "better-sqlite3";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;
const mailer = process.env.SMTP_HOST &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT || 587) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

async function sendAppointmentEmail(appointmentId, status) {
  if (!mailer || !process.env.SMTP_FROM) {
    console.warn("Email notification skipped: SMTP is not configured.");
    return false;
  }

  const appointment = db.prepare(`
    SELECT
      c.name AS customer_name,
      c.email AS customer_email,
      s.name AS service_name,
      a.appointment_date,
      a.appointment_time,
      a.status,
      w.name AS worker_name
    FROM appointments a
    JOIN customers c ON c.id = a.customer_id
    JOIN services s ON s.id = a.service_id
    LEFT JOIN workers w ON w.id = a.worker_id
    WHERE a.id = ?
  `).get(appointmentId);

  if (!appointment?.customer_email) {
    console.warn("Email notification skipped: customer has no email.");
    return false;
  }

  const messages = {
    confirmed: {
      subject: "Your salon appointment is confirmed",
      message: "Your appointment has been confirmed. We look forward to seeing you!"
    },
    cancelled: {
      subject: "Your salon appointment has been cancelled",
      message: "Your appointment has been cancelled. Please contact the salon if you need assistance."
    }
  };

  const notification = messages[status];

  if (!notification) return false;

  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM,
      to: appointment.customer_email,
      subject: notification.subject,
      text: `Hello ${appointment.customer_name},

${notification.message}

Service: ${appointment.service_name}
Date: ${appointment.appointment_date}
Time: ${appointment.appointment_time}
Worker: ${appointment.worker_name || "To be assigned"}

Thank you for choosing our salon.`
    });

    return true;
  } catch (error) {
    console.error("Appointment email failed:", error.message);
    return false;
  }
}

if (!JWT_SECRET) {
  console.error("Error: JWT_SECRET is missing from .env");
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: "20kb" }));

// =====================================================
// DATABASE
// Preserve the existing salon.db and all existing data.
// =====================================================

const db = new Database(path.join(__dirname, "salon.db"));

db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS owner_credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image TEXT,
    duration_minutes INTEGER DEFAULT 60
  );

  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT
  );

  CREATE TABLE IF NOT EXISTS appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    appointment_date TEXT NOT NULL,
    appointment_time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    FOREIGN KEY (customer_id) REFERENCES customers(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
  );

  CREATE TABLE IF NOT EXISTS offers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    discount_percentage REAL DEFAULT 0,
    active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS workers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    phone TEXT DEFAULT '',
    photo TEXT DEFAULT '',
    specialties TEXT DEFAULT '',
    experience_years INTEGER NOT NULL DEFAULT 0,
    bio TEXT DEFAULT '',
    is_active INTEGER NOT NULL DEFAULT 1,
    token_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS worker_services (
    worker_id INTEGER NOT NULL,
    service_id INTEGER NOT NULL,
    PRIMARY KEY (worker_id, service_id),
    FOREIGN KEY (worker_id) REFERENCES workers(id) ON DELETE CASCADE,
    FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
  );
`);

// =====================================================
// SAFE DATABASE MIGRATIONS
// =====================================================

function getColumns(tableName) {
  return db.prepare(`PRAGMA table_info(${tableName})`)
    .all()
    .map((column) => column.name);
}

const ownerColumns = getColumns("owner_credentials");

if (!ownerColumns.includes("token_version")) {
  db.exec(`
    ALTER TABLE owner_credentials
    ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0
  `);
}

const workerColumns = getColumns("workers");

if (!workerColumns.includes("token_version")) {
  db.exec(`
    ALTER TABLE workers
    ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0
  `);
}

const appointmentColumns = getColumns("appointments");

if (!appointmentColumns.includes("worker_id")) {
  db.exec(`
    ALTER TABLE appointments
    ADD COLUMN worker_id INTEGER REFERENCES workers(id)
  `);
}

// Initialize owner credentials only if an owner doesn't already exist.
const existingOwner = db.prepare(
  "SELECT id FROM owner_credentials WHERE id = 1"
).get();

if (!existingOwner) {
  const initialEmail = process.env.OWNER_EMAIL;
  const initialHash = process.env.OWNER_PASSWORD_HASH;

  if (initialEmail && initialHash) {
    db.prepare(`
      INSERT INTO owner_credentials (id, email, password_hash)
      VALUES (1, ?, ?)
    `).run(initialEmail.trim().toLowerCase(), initialHash);
  } else {
    console.warn(
      "Owner account not initialized. Check OWNER_EMAIL and OWNER_PASSWORD_HASH in .env."
    );
  }
}

// =====================================================
// HELPERS
// =====================================================

function sendError(res, status, message) {
  return res.status(status).json({ error: message });
}

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function validPhoto(value) {
  if (value === undefined || value === null || value === "") {
    return "";
  }

  if (typeof value !== "string" || value.length > 2000) {
    return null;
  }

  try {
    const url = new URL(value);

    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }

    return value.trim();
  } catch {
    return null;
  }
}

function publicWorker(worker) {
  return {
    id: worker.id,
    name: worker.name,
    photo: worker.photo || "",
    specialties: worker.specialties || "",
    experience_years: Number(worker.experience_years || 0),
    bio: worker.bio || ""
  };
}

function ownerWorker(worker) {
  return {
    ...publicWorker(worker),
    email: worker.email,
    phone: worker.phone || "",
    is_active: Number(worker.is_active),
    created_at: worker.created_at
  };
}

function getWorkerServices(workerId) {
  return db.prepare(`
    SELECT service_id
    FROM worker_services
    WHERE worker_id = ?
    ORDER BY service_id
  `).all(workerId).map((row) => row.service_id);
}

// If no services have been assigned to a worker, that worker can
// perform all services. Otherwise, only explicitly assigned services.
function workerCanDoService(workerId, serviceId) {
  const assigned = db.prepare(`
    SELECT COUNT(*) AS total
    FROM worker_services
    WHERE worker_id = ?
  `).get(workerId).total;

  if (assigned === 0) return true;

  return Boolean(db.prepare(`
    SELECT 1
    FROM worker_services
    WHERE worker_id = ? AND service_id = ?
  `).get(workerId, serviceId));
}

function appointmentMinutes(time) {
  const [hours, minutes] = time.split(":").map(Number);
  return hours * 60 + minutes;
}

function workerHasConflict(workerId, date, startTime, duration) {
  const newStart = appointmentMinutes(startTime);
  const newEnd = newStart + duration;

  const appointments = db.prepare(`
    SELECT
      a.appointment_time,
      s.duration_minutes
    FROM appointments a
    JOIN services s ON s.id = a.service_id
    WHERE a.worker_id = ?
      AND a.appointment_date = ?
      AND LOWER(a.status) IN ('pending', 'confirmed')
  `).all(workerId, date);

  return appointments.some((appointment) => {
    const existingStart = appointmentMinutes(appointment.appointment_time);
    const existingDuration = Number(appointment.duration_minutes || 60);
    const existingEnd = existingStart + existingDuration;

    return newStart < existingEnd && existingStart < newEnd;
  });
}

function validBookingDate(date, time) {
  if (
    typeof date !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(date) ||
    typeof time !== "string" ||
    !/^([01]\d|2[0-3]):[0-5]\d$/.test(time)
  ) {
    return false;
  }

  const parsed = new Date(`${date}T00:00:00Z`);

  if (
    Number.isNaN(parsed.getTime()) ||
    parsed.toISOString().slice(0, 10) !== date
  ) {
    return false;
  }

  const now = new Date();

  const today = [
    now.getFullYear(),
    String(now.getMonth() + 1).padStart(2, "0"),
    String(now.getDate()).padStart(2, "0")
  ].join("-");

  if (date < today) return false;

  if (date === today) {
    const [hours, minutes] = time.split(":").map(Number);
    const requestedMinutes = hours * 60 + minutes;
    const currentMinutes = now.getHours() * 60 + now.getMinutes();

    if (requestedMinutes <= currentMinutes) return false;
  }

  return true;
}

// =====================================================
// AUTHENTICATION
// =====================================================

function requireOwner(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    if (
      typeof authorization !== "string" ||
      !authorization.startsWith("Bearer ")
    ) {
      return sendError(res, 401, "Please log in as the salon owner.");
    }

    const decoded = jwt.verify(
      authorization.slice(7),
      JWT_SECRET
    );

    if (
      decoded.role !== "owner" ||
      typeof decoded.tokenVersion !== "number"
    ) {
      return sendError(res, 403, "Owner access is required.");
    }

    const owner = db.prepare(`
      SELECT email, token_version
      FROM owner_credentials
      WHERE id = 1
    `).get();

    if (
      !owner ||
      decoded.tokenVersion !== owner.token_version ||
      decoded.email?.toLowerCase() !== owner.email.toLowerCase()
    ) {
      return sendError(
        res,
        401,
        "Your session has expired. Please log in again."
      );
    }

    req.owner = { email: owner.email };
    next();
  } catch {
    return sendError(
      res,
      401,
      "Your session is invalid or expired. Please log in again."
    );
  }
}

function requireWorker(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    if (
      typeof authorization !== "string" ||
      !authorization.startsWith("Bearer ")
    ) {
      return sendError(res, 401, "Please log in as a worker.");
    }

    const decoded = jwt.verify(
      authorization.slice(7),
      JWT_SECRET
    );

    if (
      decoded.role !== "worker" ||
      !Number.isInteger(decoded.workerId) ||
      typeof decoded.tokenVersion !== "number"
    ) {
      return sendError(res, 403, "Worker access is required.");
    }

    const worker = db.prepare(`
      SELECT *
      FROM workers
      WHERE id = ?
    `).get(decoded.workerId);

    if (
      !worker ||
      worker.is_active !== 1 ||
      worker.token_version !== decoded.tokenVersion ||
      worker.email !== decoded.email
    ) {
      return sendError(
        res,
        401,
        "Your worker session is invalid or your account is inactive."
      );
    }

    req.worker = worker;
    next();
  } catch {
    return sendError(
      res,
      401,
      "Your worker session is invalid or expired. Please log in again."
    );
  }
}

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/", (req, res) => {
  res.send("SalonHub backend is running!");
});

// =====================================================
// OWNER LOGIN
// =====================================================

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!email || typeof password !== "string" || !password) {
      return sendError(res, 400, "Please enter your email and password.");
    }

    const owner = db.prepare(`
      SELECT email, password_hash, token_version
      FROM owner_credentials
      WHERE id = 1
    `).get();

    if (!owner) {
      return sendError(res, 503, "Owner login is not configured.");
    }

    const matches =
      email === owner.email.toLowerCase() &&
      await bcrypt.compare(password, owner.password_hash);

    if (!matches) {
      return sendError(res, 401, "Invalid email or password.");
    }

    const token = jwt.sign({
      role: "owner",
      email: owner.email,
      tokenVersion: owner.token_version
    }, JWT_SECRET, { expiresIn: "2h" });

    return res.json({
      message: "Owner login successful.",
      token,
      owner: { email: owner.email }
    });
  } catch (error) {
    console.error("Owner login error:", error);
    return sendError(res, 500, "Could not complete owner login.");
  }
});

// =====================================================
// OWNER ACCOUNT SETTINGS
// =====================================================

app.patch("/api/auth/credentials", requireOwner, async (req, res) => {
  try {
    const { currentPassword, newEmail, newPassword } = req.body ?? {};

    if (typeof currentPassword !== "string" || !currentPassword) {
      return sendError(res, 400, "Enter your current password.");
    }

    const owner = db.prepare(`
      SELECT email, password_hash
      FROM owner_credentials
      WHERE id = 1
    `).get();

    if (!owner || !await bcrypt.compare(currentPassword, owner.password_hash)) {
      return sendError(res, 401, "Your current password is incorrect.");
    }

    const changingEmail = newEmail !== undefined;
    const changingPassword = newPassword !== undefined;

    if (!changingEmail && !changingPassword) {
      return sendError(res, 400, "Enter a new email or password.");
    }

    let email = owner.email;
    let passwordHash = owner.password_hash;

    if (changingEmail) {
      email = normalizeEmail(newEmail);

      if (!validEmail(email)) {
        return sendError(res, 400, "Enter a valid email address.");
      }
    }

    if (changingPassword) {
      if (typeof newPassword !== "string" || newPassword.length < 8) {
        return sendError(res, 400, "Password must contain at least 8 characters.");
      }

      passwordHash = await bcrypt.hash(newPassword, 12);
    }

    db.prepare(`
      UPDATE owner_credentials
      SET email = ?,
          password_hash = ?,
          token_version = token_version + 1
      WHERE id = 1
    `).run(email, passwordHash);

    return res.json({
      message: "Login details updated. Please log in again.",
      owner: { email },
      mustLogInAgain: true
    });
  } catch (error) {
    if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
      return sendError(res, 409, "That email address is already in use.");
    }

    console.error("Update owner credentials error:", error);
    return sendError(res, 500, "Could not update owner login details.");
  }
});

// =====================================================
// SERVICES
// =====================================================

// Public: list services.
app.get("/api/services", (req, res) => {
  try {
    return res.json(db.prepare(`
      SELECT *
      FROM services
      ORDER BY name
    `).all());
  } catch (error) {
    console.error("Load services error:", error);
    return sendError(res, 500, "Could not load salon services.");
  }
});

// Owner: create service.
app.post("/api/services", requireOwner, (req, res) => {
  try {
    const { name, description, price, image, duration_minutes } = req.body ?? {};
    const duration = Number(duration_minutes ?? 60);

    if (typeof name !== "string" || !name.trim()) {
      return sendError(res, 400, "Enter a service name.");
    }

    if (name.trim().length > 120) {
      return sendError(res, 400, "Service name is too long.");
    }

    if (
      price === "" ||
      price === undefined ||
      !Number.isFinite(Number(price)) ||
      Number(price) < 0
    ) {
      return sendError(res, 400, "Enter a valid, non-negative price.");
    }

    if (!Number.isInteger(duration) || duration < 1 || duration > 1440) {
      return sendError(res, 400, "Duration must be between 1 and 1440 minutes.");
    }

    const result = db.prepare(`
      INSERT INTO services (name, description, price, image, duration_minutes)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      name.trim(),
      typeof description === "string" ? description.trim() : "",
      Number(price),
      typeof image === "string" && image.trim() ? image.trim() : null,
      duration
    );

    return res.status(201).json({
      message: "Service added successfully.",
      service: db.prepare("SELECT * FROM services WHERE id = ?")
        .get(result.lastInsertRowid)
    });
  } catch (error) {
    console.error("Add service error:", error);
    return sendError(res, 500, "Could not add the service.");
  }
});

// Owner: edit service.
app.put("/api/services/:id", requireOwner, (req, res) => {
  try {
    const id = validId(req.params.id);
    const { name, description, price, image, duration_minutes } = req.body ?? {};
    const duration = Number(duration_minutes ?? 60);

    if (!id) return sendError(res, 400, "Invalid service ID.");
    if (typeof name !== "string" || !name.trim()) {
      return sendError(res, 400, "Enter a service name.");
    }
    if (
      price === "" ||
      price === undefined ||
      !Number.isFinite(Number(price)) ||
      Number(price) < 0
    ) {
      return sendError(res, 400, "Enter a valid, non-negative price.");
    }
    if (!Number.isInteger(duration) || duration < 1 || duration > 1440) {
      return sendError(res, 400, "Duration must be between 1 and 1440 minutes.");
    }

    const result = db.prepare(`
      UPDATE services
      SET name = ?, description = ?, price = ?, image = ?, duration_minutes = ?
      WHERE id = ?
    `).run(
      name.trim(),
      typeof description === "string" ? description.trim() : "",
      Number(price),
      typeof image === "string" && image.trim() ? image.trim() : null,
      duration,
      id
    );

    if (!result.changes) return sendError(res, 404, "Service not found.");

    return res.json({
      message: "Service updated successfully.",
      service: db.prepare("SELECT * FROM services WHERE id = ?").get(id)
    });
  } catch (error) {
    console.error("Update service error:", error);
    return sendError(res, 500, "Could not update the service.");
  }
});

// Owner: delete service if no appointment history references it.
app.delete("/api/services/:id", requireOwner, (req, res) => {
  try {
    const id = validId(req.params.id);
    if (!id) return sendError(res, 400, "Invalid service ID.");

    const service = db.prepare("SELECT id FROM services WHERE id = ?").get(id);
    if (!service) return sendError(res, 404, "Service not found.");

    const used = db.prepare(`
      SELECT COUNT(*) AS total
      FROM appointments
      WHERE service_id = ?
    `).get(id).total;

    if (used > 0) {
      return sendError(
        res,
        409,
        "This service has appointment history and cannot be deleted."
      );
    }

    db.prepare("DELETE FROM worker_services WHERE service_id = ?").run(id);
    db.prepare("DELETE FROM services WHERE id = ?").run(id);

    return res.json({ message: "Service deleted successfully." });
  } catch (error) {
    console.error("Delete service error:", error);
    return sendError(res, 500, "Could not delete the service.");
  }
});

// =====================================================
// WORKER PUBLIC PROFILES
// =====================================================

// Public: active worker profiles only.
// Never return worker emails, phone numbers, or password hashes here.
app.get("/api/workers", (req, res) => {
  try {
    const workers = db.prepare(`
      SELECT id, name, photo, specialties, experience_years, bio
      FROM workers
      WHERE is_active = 1
      ORDER BY name
    `).all();

    return res.json(workers);
  } catch (error) {
    console.error("Public worker list error:", error);
    return sendError(res, 500, "Could not load salon workers.");
  }
});

// =====================================================
// OWNER: WORKER MANAGEMENT
// =====================================================

// Owner: list all workers, including inactive workers.
app.get("/api/workers/owner", requireOwner, (req, res) => {
  try {
    const workers = db.prepare(`
      SELECT *
      FROM workers
      ORDER BY name
    `).all();

    return res.json(workers.map((worker) => ({
      ...ownerWorker(worker),
      serviceIds: getWorkerServices(worker.id)
    })));
  } catch (error) {
    console.error("Owner worker list error:", error);
    return sendError(res, 500, "Could not load worker accounts.");
  }
});

// Owner: create a worker account.
app.post("/api/workers", requireOwner, async (req, res) => {
  try {
    const {
      name,
      email,
      password,
      phone,
      photo,
      specialties,
      experience_years,
      bio,
      serviceIds
    } = req.body ?? {};

    const workerName = typeof name === "string" ? name.trim() : "";
    const workerEmail = normalizeEmail(email);

    if (!workerName || workerName.length > 120) {
      return sendError(res, 400, "Enter a valid worker name.");
    }

    if (!validEmail(workerEmail)) {
      return sendError(res, 400, "Enter a valid worker email address.");
    }

    if (typeof password !== "string" || password.length < 8) {
      return sendError(res, 400, "Worker password must contain at least 8 characters.");
    }

    const years = Number(experience_years ?? 0);

    if (!Number.isInteger(years) || years < 0 || years > 80) {
      return sendError(res, 400, "Experience must be between 0 and 80 years.");
    }

    const photoUrl = validPhoto(photo);

    if (photoUrl === null) {
      return sendError(res, 400, "Photo must be a valid HTTP or HTTPS URL.");
    }

    if (
      phone !== undefined && typeof phone !== "string" ||
      specialties !== undefined && typeof specialties !== "string" ||
      bio !== undefined && typeof bio !== "string"
    ) {
      return sendError(res, 400, "Invalid worker profile details.");
    }

    if (
      (phone || "").length > 30 ||
      (specialties || "").length > 500 ||
      (bio || "").length > 2000
    ) {
      return sendError(res, 400, "One or more worker profile fields are too long.");
    }

    const hash = await bcrypt.hash(password, 12);

    const createWorker = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO workers (
          name, email, password_hash, phone, photo,
          specialties, experience_years, bio
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        workerName,
        workerEmail,
        hash,
        phone || "",
        photoUrl,
        specialties || "",
        years,
        bio || ""
      );

      const workerId = Number(result.lastInsertRowid);

      if (serviceIds !== undefined) {
        if (!Array.isArray(serviceIds)) {
          throw new Error("serviceIds must be an array.");
        }

        const insertAssignment = db.prepare(`
          INSERT INTO worker_services (worker_id, service_id)
          VALUES (?, ?)
        `);

        for (const serviceId of serviceIds) {
          const id = validId(serviceId);

          if (!id || !db.prepare(
            "SELECT id FROM services WHERE id = ?"
          ).get(id)) {
            throw new Error(`Invalid service ID: ${serviceId}`);
          }

          insertAssignment.run(workerId, id);
        }
      }

      return workerId;
    });

    const workerId = createWorker();
    const worker = db.prepare("SELECT * FROM workers WHERE id = ?")
      .get(workerId);

    return res.status(201).json({
      message: "Worker account created successfully.",
      worker: {
        ...ownerWorker(worker),
        serviceIds: getWorkerServices(workerId)
      }
    });
  } catch (error) {
    if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
      return sendError(res, 409, "A worker with that email already exists.");
    }

    if (
      error.message?.startsWith("Invalid service ID") ||
      error.message === "serviceIds must be an array."
    ) {
      return sendError(res, 400, error.message);
    }

    console.error("Create worker error:", error);
    return sendError(res, 500, "Could not create the worker account.");
  }
});

// Owner: update the services a worker is allowed to perform.
app.put("/api/workers/:id/services", requireOwner, (req, res) => {
  // Owner: update a worker's profile without deleting their history.
app.patch("/api/workers/:id", requireOwner, async (req, res) => {
  try {
    const workerId = validId(req.params.id);

    if (!workerId) {
      return sendError(res, 400, "Invalid worker ID.");
    }

    const existing = db.prepare(
      "SELECT * FROM workers WHERE id = ?"
    ).get(workerId);

    if (!existing) {
      return sendError(res, 404, "Worker not found.");
    }

    const {
      name,
      email,
      password,
      phone,
      photo,
      specialties,
      experience,
      experience_years,
      bio
    } = req.body ?? {};

    const workerName =
      name === undefined ? existing.name :
      typeof name === "string" ? name.trim() : "";

    const workerEmail =
      email === undefined ? existing.email :
      normalizeEmail(email);

    if (!workerName || workerName.length > 120) {
      return sendError(res, 400, "Enter a valid worker name.");
    }

    if (!validEmail(workerEmail)) {
      return sendError(res, 400, "Enter a valid worker email address.");
    }

    const yearsInput = experience_years ?? experience;
    const years = yearsInput === undefined
      ? existing.experience_years
      : Number(yearsInput);

    if (!Number.isInteger(years) || years < 0 || years > 80) {
      return sendError(res, 400, "Experience must be between 0 and 80 years.");
    }

    const workerPhone = phone === undefined ? existing.phone : phone;
    const workerSpecialties =
      specialties === undefined ? existing.specialties : specialties;
    const workerBio = bio === undefined ? existing.bio : bio;
    const workerPhoto = photo === undefined ? existing.photo : validPhoto(photo);

    if (
      typeof workerPhone !== "string" ||
      typeof workerSpecialties !== "string" ||
      typeof workerBio !== "string"
    ) {
      return sendError(res, 400, "Invalid worker profile details.");
    }

    if (
      workerPhone.length > 30 ||
      workerSpecialties.length > 500 ||
      workerBio.length > 2000
    ) {
      return sendError(res, 400, "One or more worker profile fields are too long.");
    }

    if (workerPhoto === null) {
      return sendError(res, 400, "Photo must be a valid HTTP or HTTPS URL.");
    }

    let passwordHash = existing.password_hash;

    if (password !== undefined && password !== "") {
      if (typeof password !== "string" || password.length < 8) {
        return sendError(res, 400, "Password must contain at least 8 characters.");
      }

      passwordHash = await bcrypt.hash(password, 12);
    }

    db.prepare(`
      UPDATE workers
      SET name = ?,
          email = ?,
          password_hash = ?,
          phone = ?,
          photo = ?,
          specialties = ?,
          experience_years = ?,
          bio = ?,
          token_version = token_version + 1
      WHERE id = ?
    `).run(
      workerName,
      workerEmail,
      passwordHash,
      workerPhone,
      workerPhoto,
      workerSpecialties,
      years,
      workerBio,
      workerId
    );

    const updated = db.prepare(
      "SELECT * FROM workers WHERE id = ?"
    ).get(workerId);

    return res.json({
      message: "Worker profile updated successfully.",
      worker: {
        ...ownerWorker(updated),
        serviceIds: getWorkerServices(workerId)
      }
    });
  } catch (error) {
    if (String(error.code || "").includes("SQLITE_CONSTRAINT")) {
      return sendError(res, 409, "A worker with that email already exists.");
    }

    console.error("Update worker profile error:", error);
    return sendError(res, 500, "Could not update the worker profile.");
  }
});
  try {
    const workerId = validId(req.params.id);
    const { serviceIds } = req.body ?? {};

    if (!workerId) return sendError(res, 400, "Invalid worker ID.");

    const worker = db.prepare("SELECT id FROM workers WHERE id = ?")
      .get(workerId);

    if (!worker) return sendError(res, 404, "Worker not found.");

    if (!Array.isArray(serviceIds)) {
      return sendError(res, 400, "serviceIds must be an array.");
    }

    const ids = [...new Set(serviceIds.map(validId))];

    if (ids.some((id) => !id)) {
      return sendError(res, 400, "One or more service IDs are invalid.");
    }

    for (const id of ids) {
      if (!db.prepare("SELECT id FROM services WHERE id = ?").get(id)) {
        return sendError(res, 400, `Service ${id} does not exist.`);
      }
    }

    const save = db.transaction(() => {
      db.prepare("DELETE FROM worker_services WHERE worker_id = ?")
        .run(workerId);

      const insert = db.prepare(`
        INSERT INTO worker_services (worker_id, service_id)
        VALUES (?, ?)
      `);

      for (const id of ids) {
        insert.run(workerId, id);
      }
    });

    save();

    return res.json({
      message: "Worker services updated successfully.",
      serviceIds: ids
    });
  } catch (error) {
    console.error("Update worker services error:", error);
    return sendError(res, 500, "Could not update worker services.");
  }
});

// Owner: activate or deactivate a worker.
// Deactivation invalidates the worker's existing login token.
app.patch("/api/workers/:id/status", requireOwner, (req, res) => {
  try {
    const workerId = validId(req.params.id);
    const { is_active } = req.body ?? {};

    if (!workerId) return sendError(res, 400, "Invalid worker ID.");

    if (typeof is_active !== "boolean") {
      return sendError(res, 400, "is_active must be true or false.");
    }

    const result = db.prepare(`
      UPDATE workers
      SET is_active = ?,
          token_version = token_version + 1
      WHERE id = ?
    `).run(is_active ? 1 : 0, workerId);

    if (!result.changes) return sendError(res, 404, "Worker not found.");

    return res.json({
      message: is_active
        ? "Worker activated successfully."
        : "Worker deactivated successfully.",
      workerId,
      is_active
    });
  } catch (error) {
    console.error("Update worker status error:", error);
    return sendError(res, 500, "Could not update worker status.");
  }
});

// =====================================================
// WORKER LOGIN AND PROFILE
// =====================================================

app.post("/api/workers/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;

    if (!email || typeof password !== "string" || !password) {
      return sendError(res, 400, "Enter your worker email and password.");
    }

    const worker = db.prepare(`
      SELECT *
      FROM workers
      WHERE email = ?
    `).get(email);

    if (
      !worker ||
      worker.is_active !== 1 ||
      !await bcrypt.compare(password, worker.password_hash)
    ) {
      return sendError(res, 401, "Invalid login details or inactive account.");
    }

    const token = jwt.sign({
      role: "worker",
      workerId: worker.id,
      email: worker.email,
      tokenVersion: worker.token_version
    }, JWT_SECRET, { expiresIn: "2h" });

    return res.json({
      message: "Worker login successful.",
      token,
      worker: publicWorker(worker)
    });
  } catch (error) {
    console.error("Worker login error:", error);
    return sendError(res, 500, "Could not complete worker login.");
  }
});

// Worker: view own profile.
app.get("/api/workers/me", requireWorker, (req, res) => {
  return res.json({
    worker: {
      ...publicWorker(req.worker),
      email: req.worker.email,
      phone: req.worker.phone || ""
    }
  });
});

// Worker: edit own profile. Workers cannot edit their email,
// password, activation status, or service permissions through this route.
app.patch("/api/workers/me", requireWorker, (req, res) => {
  try {
    const { name, phone, photo, specialties, experience_years, bio } =
      req.body ?? {};

    const updatedName = name === undefined ? req.worker.name : name;
    const updatedPhone = phone === undefined ? req.worker.phone : phone;
    const updatedSpecialties =
      specialties === undefined ? req.worker.specialties : specialties;
    const updatedBio = bio === undefined ? req.worker.bio : bio;
    const updatedYears = experience_years === undefined
      ? req.worker.experience_years
      : Number(experience_years);

    if (
      typeof updatedName !== "string" ||
      !updatedName.trim() ||
      updatedName.trim().length > 120
    ) {
      return sendError(res, 400, "Enter a valid worker name.");
    }

    if (
      typeof updatedPhone !== "string" ||
      updatedPhone.length > 30 ||
      typeof updatedSpecialties !== "string" ||
      updatedSpecialties.length > 500 ||
      typeof updatedBio !== "string" ||
      updatedBio.length > 2000
    ) {
      return sendError(res, 400, "Invalid profile information.");
    }

    if (
      !Number.isInteger(updatedYears) ||
      updatedYears < 0 ||
      updatedYears > 80
    ) {
      return sendError(res, 400, "Experience must be between 0 and 80 years.");
    }

    const photoUrl = photo === undefined
      ? req.worker.photo || ""
      : validPhoto(photo);

    if (photoUrl === null) {
      return sendError(res, 400, "Photo must be a valid HTTP or HTTPS URL.");
    }

    db.prepare(`
      UPDATE workers
      SET name = ?, phone = ?, photo = ?,
          specialties = ?, experience_years = ?, bio = ?
      WHERE id = ?
    `).run(
      updatedName.trim(),
      updatedPhone,
      photoUrl,
      updatedSpecialties,
      updatedYears,
      updatedBio,
      req.worker.id
    );

    const updated = db.prepare("SELECT * FROM workers WHERE id = ?")
      .get(req.worker.id);

    return res.json({
      message: "Profile updated successfully.",
      worker: {
        ...publicWorker(updated),
        email: updated.email,
        phone: updated.phone || ""
      }
    });
  } catch (error) {
    console.error("Update worker profile error:", error);
    return sendError(res, 500, "Could not update worker profile.");
  }
});

// Worker: view their own assigned appointments only.
app.get("/api/workers/me/appointments", requireWorker, (req, res) => {
  try {
    const appointments = db.prepare(`
      SELECT
        a.id,
        c.name AS customer_name,
        c.phone AS customer_phone,
        c.email AS customer_email,
        s.name AS service_name,
        s.price AS service_price,
        s.duration_minutes,
        a.appointment_date,
        a.appointment_time,
        a.status
      FROM appointments a
      JOIN customers c ON c.id = a.customer_id
      JOIN services s ON s.id = a.service_id
      WHERE a.worker_id = ?
      ORDER BY a.appointment_date, a.appointment_time
    `).all(req.worker.id);

    return res.json(appointments);
  } catch (error) {
    console.error("Worker appointments error:", error);
    return sendError(res, 500, "Could not load your appointments.");
  }
});
// =====================================================
// PUBLIC APPOINTMENT AVAILABILITY
// Salon hours: 08:00–22:00
// Slots: every 30 minutes
// =====================================================

app.get("/api/availability", (req, res) => {
  try {
    const { date, serviceId, workerId } = req.query;

    const serviceIdNumber = validId(serviceId);

    if (
      !serviceIdNumber ||
      typeof date !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(date)
    ) {
      return sendError(res, 400, "Select a valid service and date.");
    }

    const parsedDate = new Date(`${date}T00:00:00Z`);

    if (
      Number.isNaN(parsedDate.getTime()) ||
      parsedDate.toISOString().slice(0, 10) !== date
    ) {
      return sendError(res, 400, "Invalid appointment date.");
    }

    const service = db.prepare(`
      SELECT id, duration_minutes
      FROM services
      WHERE id = ?
    `).get(serviceIdNumber);

    if (!service) {
      return sendError(res, 404, "Service not found.");
    }

    let selectedWorkerId = null;

    if (
      workerId !== undefined &&
      workerId !== "" &&
      workerId !== "any"
    ) {
      selectedWorkerId = validId(workerId);

      if (!selectedWorkerId) {
        return sendError(res, 400, "Invalid worker selection.");
      }

      const worker = db.prepare(`
        SELECT id
        FROM workers
        WHERE id = ? AND is_active = 1
      `).get(selectedWorkerId);

      if (!worker) {
        return sendError(res, 404, "Active worker not found.");
      }

      if (!workerCanDoService(selectedWorkerId, serviceIdNumber)) {
        return res.json({
          date,
          serviceId: serviceIdNumber,
          workerId: selectedWorkerId,
          availableTimes: []
        });
      }
    }

    const duration = Number(service.duration_minutes || 60);

    if (!Number.isFinite(duration) || duration < 1) {
      return sendError(res, 400, "Invalid service duration.");
    }

    const workers = selectedWorkerId
      ? [{ id: selectedWorkerId }]
      : db.prepare(`
          SELECT id
          FROM workers
          WHERE is_active = 1
          ORDER BY name
        `).all();

    const availableTimes = [];
    const openingMinutes = 8 * 60;
    const closingMinutes = 22 * 60;

    for (
      let start = openingMinutes;
      start + duration <= closingMinutes;
      start += 30
    ) {
      const time =
        `${String(Math.floor(start / 60)).padStart(2, "0")}:` +
        `${String(start % 60).padStart(2, "0")}`;

      if (!validBookingDate(date, time)) continue;

      const availableWorker = workers.find((worker) =>
        workerCanDoService(worker.id, serviceIdNumber) &&
        !workerHasConflict(worker.id, date, time, duration)
      );

      if (availableWorker) {
        availableTimes.push(time);
      }
    }

    return res.json({
      date,
      serviceId: serviceIdNumber,
      workerId: selectedWorkerId,
      availableTimes
    });
  } catch (error) {
    console.error("Availability lookup error:", error);
    return sendError(res, 500, "Could not load available appointment times.");
  }
});

// =====================================================
// CUSTOMER BOOKING
// =====================================================

// Public booking route.
//
// Send workerId with a worker's ID to request that worker.
// Send workerId: null, or omit it, to request any available worker.
app.post("/api/appointments", (req, res) => {
  try {
    const {
      customerName,
      phone,
      email,
      serviceId,
      appointmentDate,
      appointmentTime,
      workerId: requestedWorkerId
    } = req.body ?? {};

    if (
      typeof customerName !== "string" ||
      !customerName.trim() ||
      customerName.trim().length > 120 ||
      typeof phone !== "string" ||
      !phone.trim() ||
      phone.trim().length > 30
    ) {
      return sendError(res, 400, "Enter your name and phone number.");
    }

    if (
      email !== undefined &&
      email !== null &&
      typeof email !== "string"
    ) {
      return sendError(res, 400, "Invalid email address.");
    }

    if (typeof email === "string" && email.trim() && !validEmail(email.trim())) {
      return sendError(res, 400, "Enter a valid email address.");
    }

    const serviceIdNumber = validId(serviceId);

    if (!serviceIdNumber) {
      return sendError(res, 400, "Select a valid salon service.");
    }

    if (!validBookingDate(appointmentDate, appointmentTime)) {
      return sendError(
        res,
        400,
        "Choose a valid future date and time."
      );
    }

    const service = db.prepare(`
      SELECT id, name, duration_minutes
      FROM services
      WHERE id = ?
    `).get(serviceIdNumber);

    if (!service) {
      return sendError(res, 400, "The selected service does not exist.");
    }

    let chosenWorkerId = null;

    if (
      requestedWorkerId !== undefined &&
      requestedWorkerId !== null &&
      requestedWorkerId !== ""
    ) {
      chosenWorkerId = validId(requestedWorkerId);

      if (!chosenWorkerId) {
        return sendError(res, 400, "Invalid worker selection.");
      }

      const worker = db.prepare(`
        SELECT id, is_active
        FROM workers
        WHERE id = ?
      `).get(chosenWorkerId);

      if (!worker || worker.is_active !== 1) {
        return sendError(
          res,
          409,
          "That worker is not currently available for booking."
        );
      }

      if (!workerCanDoService(chosenWorkerId, serviceIdNumber)) {
        return sendError(
          res,
          409,
          "That worker does not provide the selected service."
        );
      }

      if (
        workerHasConflict(
          chosenWorkerId,
          appointmentDate,
          appointmentTime,
          Number(service.duration_minutes || 60)
        )
      ) {
        return sendError(
          res,
          409,
          "That worker is already booked during this time. Please choose another worker or time."
        );
      }
    } else {
      // Any available worker: find an active worker who can perform
      // this service and has no overlapping appointment.
      const candidates = db.prepare(`
        SELECT w.id
        FROM workers w
        WHERE w.is_active = 1
        ORDER BY w.name
      `).all();

      for (const candidate of candidates) {
        if (!workerCanDoService(candidate.id, serviceIdNumber)) {
          continue;
        }

        if (
          !workerHasConflict(
            candidate.id,
            appointmentDate,
            appointmentTime,
            Number(service.duration_minutes || 60)
          )
        ) {
          chosenWorkerId = candidate.id;
          break;
        }
      }

      if (!chosenWorkerId) {
        return sendError(
          res,
          409,
          "No worker is available for that service and time. Please choose another time."
        );
      }
    }

    // Recheck availability inside the transaction before saving.
    // This also ensures the customer and appointment are saved together.
    const createBooking = db.transaction(() => {
      const activeWorker = db.prepare(`
        SELECT id, is_active
        FROM workers
        WHERE id = ?
      `).get(chosenWorkerId);

      if (!activeWorker || activeWorker.is_active !== 1) {
        throw new Error("WORKER_UNAVAILABLE");
      }

      if (!workerCanDoService(chosenWorkerId, serviceIdNumber)) {
        throw new Error("WORKER_SERVICE_MISMATCH");
      }

      if (
        workerHasConflict(
          chosenWorkerId,
          appointmentDate,
          appointmentTime,
          Number(service.duration_minutes || 60)
        )
      ) {
        throw new Error("WORKER_TIME_CONFLICT");
      }

      const customerResult = db.prepare(`
        INSERT INTO customers (name, phone, email)
        VALUES (?, ?, ?)
      `).run(
        customerName.trim(),
        phone.trim(),
        typeof email === "string" && email.trim()
          ? email.trim()
          : null
      );

      const appointmentResult = db.prepare(`
        INSERT INTO appointments (
          customer_id,
          service_id,
          worker_id,
          appointment_date,
          appointment_time,
          status
        )
        VALUES (?, ?, ?, ?, ?, 'pending')
      `).run(
        customerResult.lastInsertRowid,
        serviceIdNumber,
        chosenWorkerId,
        appointmentDate,
        appointmentTime
      );

      return Number(appointmentResult.lastInsertRowid);
    });

    const appointmentId = createBooking();

    const worker = db.prepare(`
      SELECT id, name
      FROM workers
      WHERE id = ?
    `).get(chosenWorkerId);

    return res.status(201).json({
      message: "Booking submitted successfully. Awaiting salon confirmation.",
      appointmentId,
      status: "pending",
      workerId: chosenWorkerId,
      workerName: worker.name
    });
  } catch (error) {
    if (error.message === "WORKER_UNAVAILABLE") {
      return sendError(res, 409, "That worker is no longer available.");
    }

    if (error.message === "WORKER_SERVICE_MISMATCH") {
      return sendError(res, 409, "That worker does not provide this service.");
    }

    if (error.message === "WORKER_TIME_CONFLICT") {
      return sendError(
        res,
        409,
        "That time slot has just been booked. Please choose another time."
      );
    }

    console.error("Booking error:", error);
    return sendError(res, 500, "Could not save your booking. Please try again.");
  }
});

// =====================================================
// OWNER: VIEW APPOINTMENTS
// =====================================================

app.get("/api/appointments", requireOwner, (req, res) => {
  try {
    const appointments = db.prepare(`
      SELECT
        a.id,
        c.name AS customer_name,
        c.phone AS customer_phone,
        c.email AS customer_email,
        s.name AS service_name,
        s.price AS service_price,
        s.duration_minutes,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.worker_id,
        w.name AS worker_name
      FROM appointments a
      JOIN customers c ON c.id = a.customer_id
      JOIN services s ON s.id = a.service_id
      LEFT JOIN workers w ON w.id = a.worker_id
      ORDER BY a.appointment_date, a.appointment_time
    `).all();

    return res.json(appointments);
  } catch (error) {
    console.error("Load appointments error:", error);
    return sendError(res, 500, "Could not load appointments.");
  }
});
// OWNER: UPDATE APPOINTMENT STATUS

app.patch("/api/appointments/:id", requireOwner, async (req, res) => {
  try {
    const id = validId(req.params.id);
    const { status } = req.body ?? {};

    const allowedStatuses = [
      "pending",
      "confirmed",
      "cancelled",
      "completed"
    ];

    if (!id) {
      return sendError(res, 400, "Invalid appointment ID.");
    }

    if (!allowedStatuses.includes(status)) {
      return sendError(res, 400, "Invalid appointment status.");
    }

    const appointment = db.prepare(`
      SELECT id, status
      FROM appointments
      WHERE id = ?
    `).get(id);

    if (!appointment) {
      return sendError(res, 404, "Appointment not found.");
    }

    db.prepare(`
      UPDATE appointments
      SET status = ?
      WHERE id = ?
    `).run(status, id);

    let emailSent = false;
    let emailMessage = "No email was sent.";

    if (
      status !== appointment.status &&
      ["confirmed", "cancelled"].includes(status)
    ) {
      emailSent = await sendAppointmentEmail(id, status);

      emailMessage = emailSent
        ? "Customer email sent successfully."
        : "Status saved, but the customer email was not sent. Check SMTP configuration and server logs.";
    }

    return res.json({
      message: "Appointment status updated successfully.",
      id,
      status,
      emailSent,
      emailMessage
    });
  } catch (error) {
    console.error("Update appointment status error:", error);
    return sendError(res, 500, "Could not update appointment status.");
  }
});

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {
  console.log(`SalonHub backend running at http://localhost:${PORT}`);
});