import "dotenv/config";
import express from "express";
import Database from "better-sqlite3";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error("Error: JWT_SECRET is missing from .env");
  process.exit(1);
}

app.use(cors());
app.use(express.json({ limit: "20kb" }));

// Connect to the existing database. Do not delete salon.db.
const db = new Database(path.join(__dirname, "salon.db"));
db.pragma("foreign_keys = ON");

// Owner credentials.
db.exec(`
  CREATE TABLE IF NOT EXISTS owner_credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    token_version INTEGER NOT NULL DEFAULT 0
  );
`);

const credentialColumns = db
  .prepare("PRAGMA table_info(owner_credentials)")
  .all()
  .map((column) => column.name);

if (!credentialColumns.includes("token_version")) {
  db.exec(`
    ALTER TABLE owner_credentials
    ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0
  `);
}

// Import existing credentials from .env only if no owner exists.
const existingOwner = db
  .prepare("SELECT id FROM owner_credentials WHERE id = 1")
  .get();

if (!existingOwner) {
  const initialEmail = process.env.OWNER_EMAIL;
  const initialPasswordHash = process.env.OWNER_PASSWORD_HASH;

  if (initialEmail && initialPasswordHash) {
    db.prepare(`
      INSERT INTO owner_credentials (id, email, password_hash)
      VALUES (1, ?, ?)
    `).run(initialEmail.trim().toLowerCase(), initialPasswordHash);
  } else {
    console.warn(
      "Owner credentials are missing. Configure OWNER_EMAIL and OWNER_PASSWORD_HASH in .env for initial setup."
    );
  }
}

// Services table.
db.exec(`
  CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    image TEXT,
    duration_minutes INTEGER DEFAULT 60
  );
`);

// Customers table.
db.exec(`
  CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT
  );
`);

// Appointments table.
db.exec(`
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
`);

// Offers table.
db.exec(`
  CREATE TABLE IF NOT EXISTS offers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    discount_percentage REAL DEFAULT 0,
    active INTEGER DEFAULT 1
  );
`);

// Health check.
app.get("/", (req, res) => {
  res.send("SalonHub backend is running!");
});

// PUBLIC: List salon services.
app.get("/api/services", (req, res) => {
  try {
    const services = db.prepare(`
      SELECT *
      FROM services
      ORDER BY name
    `).all();

    return res.json(services);
  } catch (error) {
    console.error("Error loading services:", error);

    return res.status(500).json({
      error: "Could not load salon services."
    });
  }
});

// OWNER LOGIN.
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body ?? {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Please enter your email and password."
      });
    }

    const owner = db.prepare(`
      SELECT email, password_hash, token_version
      FROM owner_credentials
      WHERE id = 1
    `).get();

    if (!owner) {
      return res.status(503).json({
        error: "Owner login is not configured."
      });
    }

    const emailMatches =
      email.trim().toLowerCase() === owner.email.toLowerCase();

    const passwordMatches = await bcrypt.compare(
      password,
      owner.password_hash
    );

    if (!emailMatches || !passwordMatches) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const token = jwt.sign(
      {
        role: "owner",
        email: owner.email,
        tokenVersion: owner.token_version
      },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    return res.json({
      message: "Owner login successful.",
      token,
      owner: {
        email: owner.email
      }
    });
  } catch (error) {
    console.error("Owner login error:", error);

    return res.status(500).json({
      error: "Could not complete login."
    });
  }
});

// OWNER AUTHENTICATION MIDDLEWARE.
function requireOwner(req, res, next) {
  try {
    const authorization = req.headers.authorization;

    if (
      typeof authorization !== "string" ||
      !authorization.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        error: "Please log in as the salon owner."
      });
    }

    const token = authorization.slice(7);
    const decoded = jwt.verify(token, JWT_SECRET);

    if (
      !decoded ||
      typeof decoded !== "object" ||
      decoded.role !== "owner" ||
      typeof decoded.tokenVersion !== "number"
    ) {
      return res.status(403).json({
        error: "Owner access is required. Please log in again."
      });
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
      return res.status(401).json({
        error: "Your session is no longer valid. Please log in again."
      });
    }

    req.owner = { email: owner.email };

    next();
  } catch {
    return res.status(401).json({
      error: "Your session is invalid or expired. Please log in again."
    });
  }
}

// =====================================================
// SERVICES & PRICES MANAGEMENT
// All create, update and delete operations require login.
// =====================================================

// OWNER: Add a service.
app.post("/api/services", requireOwner, (req, res) => {
  try {
    const {
      name,
      description,
      price,
      image,
      duration_minutes
    } = req.body ?? {};

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        error: "Enter a service name."
      });
    }

    if (
      price === undefined ||
      price === null ||
      price === "" ||
      !Number.isFinite(Number(price)) ||
      Number(price) < 0
    ) {
      return res.status(400).json({
        error: "Enter a valid, non-negative price."
      });
    }

    const duration = Number(duration_minutes ?? 60);

    if (
      !Number.isInteger(duration) ||
      duration < 1 ||
      duration > 1440
    ) {
      return res.status(400).json({
        error: "Duration must be between 1 and 1440 minutes."
      });
    }

    const result = db.prepare(`
      INSERT INTO services (
        name,
        description,
        price,
        image,
        duration_minutes
      )
      VALUES (?, ?, ?, ?, ?)
    `).run(
      name.trim(),
      typeof description === "string" ? description.trim() : "",
      Number(price),
      typeof image === "string" && image.trim()
        ? image.trim()
        : null,
      duration
    );

    const service = db.prepare(`
      SELECT * FROM services WHERE id = ?
    `).get(result.lastInsertRowid);

    return res.status(201).json({
      message: "Service added successfully.",
      service
    });
  } catch (error) {
    console.error("Add service error:", error);

    return res.status(500).json({
      error: "Could not add the service."
    });
  }
});

// OWNER: Edit a service.
app.put("/api/services/:id", requireOwner, (req, res) => {
  try {
    const id = Number(req.params.id);

    const {
      name,
      description,
      price,
      image,
      duration_minutes
    } = req.body ?? {};

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({
        error: "Invalid service ID."
      });
    }

    if (typeof name !== "string" || !name.trim()) {
      return res.status(400).json({
        error: "Enter a service name."
      });
    }

    if (
      price === undefined ||
      price === null ||
      price === "" ||
      !Number.isFinite(Number(price)) ||
      Number(price) < 0
    ) {
      return res.status(400).json({
        error: "Enter a valid, non-negative price."
      });
    }

    const duration = Number(duration_minutes ?? 60);

    if (
      !Number.isInteger(duration) ||
      duration < 1 ||
      duration > 1440
    ) {
      return res.status(400).json({
        error: "Duration must be between 1 and 1440 minutes."
      });
    }

    const result = db.prepare(`
      UPDATE services
      SET name = ?,
          description = ?,
          price = ?,
          image = ?,
          duration_minutes = ?
      WHERE id = ?
    `).run(
      name.trim(),
      typeof description === "string" ? description.trim() : "",
      Number(price),
      typeof image === "string" && image.trim()
        ? image.trim()
        : null,
      duration,
      id
    );

    if (result.changes === 0) {
      return res.status(404).json({
        error: "Service not found."
      });
    }

    const service = db.prepare(`
      SELECT * FROM services WHERE id = ?
    `).get(id);

    return res.json({
      message: "Service updated successfully.",
      service
    });
  } catch (error) {
    console.error("Update service error:", error);

    return res.status(500).json({
      error: "Could not update the service."
    });
  }
});

// OWNER: Delete a service.
// Preserve services referenced by existing appointments.
app.delete("/api/services/:id", requireOwner, (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({
        error: "Invalid service ID."
      });
    }

    const existing = db.prepare(`
      SELECT id FROM services WHERE id = ?
    `).get(id);

    if (!existing) {
      return res.status(404).json({
        error: "Service not found."
      });
    }

    const appointmentCount = db.prepare(`
      SELECT COUNT(*) AS total
      FROM appointments
      WHERE service_id = ?
    `).get(id).total;

    if (appointmentCount > 0) {
      return res.status(409).json({
        error:
          "This service has existing appointments. It cannot be deleted because appointment history must be preserved."
      });
    }

    db.prepare(`
      DELETE FROM services WHERE id = ?
    `).run(id);

    return res.json({
      message: "Service deleted successfully."
    });
  } catch (error) {
    console.error("Delete service error:", error);

    return res.status(500).json({
      error: "Could not delete the service."
    });
  }
});

// =====================================================
// OWNER LOGIN CREDENTIALS SETTINGS
// =====================================================

app.patch("/api/auth/credentials", requireOwner, async (req, res) => {
  try {
    const { currentPassword, newEmail, newPassword } = req.body ?? {};

    if (
      typeof currentPassword !== "string" ||
      !currentPassword
    ) {
      return res.status(400).json({
        error: "Enter your current password to save changes."
      });
    }

    const owner = db.prepare(`
      SELECT email, password_hash
      FROM owner_credentials
      WHERE id = 1
    `).get();

    if (!owner) {
      return res.status(404).json({
        error: "Owner account was not found."
      });
    }

    const passwordMatches = await bcrypt.compare(
      currentPassword,
      owner.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Your current password is incorrect."
      });
    }

    const changingEmail = newEmail !== undefined;
    const changingPassword = newPassword !== undefined;

    if (!changingEmail && !changingPassword) {
      return res.status(400).json({
        error: "Enter a new email address or a new password."
      });
    }

    let emailToSave = owner.email;

    if (changingEmail) {
      if (
        typeof newEmail !== "string" ||
        !newEmail.trim() ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail.trim())
      ) {
        return res.status(400).json({
          error: "Enter a valid new email address."
        });
      }

      emailToSave = newEmail.trim().toLowerCase();
    }

    let passwordHashToSave = owner.password_hash;

    if (changingPassword) {
      if (
        typeof newPassword !== "string" ||
        newPassword.length < 8
      ) {
        return res.status(400).json({
          error: "Your new password must be at least 8 characters long."
        });
      }

      passwordHashToSave = await bcrypt.hash(newPassword, 12);
    }

    db.prepare(`
      UPDATE owner_credentials
      SET email = ?,
          password_hash = ?,
          token_version = token_version + 1
      WHERE id = 1
    `).run(emailToSave, passwordHashToSave);

    return res.json({
      message: "Login details updated successfully. Please log in again.",
      owner: { email: emailToSave },
      mustLogInAgain: true
    });
  } catch (error) {
    if (String(error?.code || "").includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({
        error: "That email address is already in use."
      });
    }

    console.error("Error updating owner credentials:", error);

    return res.status(500).json({
      error: "Could not update owner login details."
    });
  }
});

// =====================================================
// CUSTOMER BOOKINGS
// =====================================================

// PUBLIC: Create an appointment.
app.post("/api/appointments", (req, res) => {
  try {
    const {
      customerName,
      phone,
      email,
      serviceId,
      appointmentDate,
      appointmentTime
    } = req.body ?? {};

    if (
      typeof customerName !== "string" ||
      !customerName.trim() ||
      typeof phone !== "string" ||
      !phone.trim() ||
      !serviceId ||
      !appointmentDate ||
      !appointmentTime
    ) {
      return res.status(400).json({
        error: "Please fill in all required booking fields."
      });
    }

    if (
      typeof appointmentDate !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(appointmentDate) ||
      typeof appointmentTime !== "string" ||
      !/^\d{2}:\d{2}$/.test(appointmentTime)
    ) {
      return res.status(400).json({
        error: "Please provide a valid appointment date and time."
      });
    }

    const parsedDate = new Date(`${appointmentDate}T00:00:00Z`);

    if (
      Number.isNaN(parsedDate.getTime()) ||
      parsedDate.toISOString().slice(0, 10) !== appointmentDate
    ) {
      return res.status(400).json({
        error: "Please provide a valid appointment date."
      });
    }

    const [hours, minutes] = appointmentTime.split(":").map(Number);

    if (
      hours > 23 ||
      minutes > 59
    ) {
      return res.status(400).json({
        error: "Please provide a valid appointment time."
      });
    }

    const today = new Date();

    const localToday = [
      today.getFullYear(),
      String(today.getMonth() + 1).padStart(2, "0"),
      String(today.getDate()).padStart(2, "0")
    ].join("-");

    if (appointmentDate < localToday) {
      return res.status(400).json({
        error: "Please choose today or a future date."
      });
    }

    const service = db.prepare(`
      SELECT id
      FROM services
      WHERE id = ?
    `).get(Number(serviceId));

    if (!service) {
      return res.status(400).json({
        error: "The selected salon service does not exist."
      });
    }

    const existingAppointment = db.prepare(`
      SELECT id
      FROM appointments
      WHERE appointment_date = ?
        AND appointment_time = ?
        AND status != 'cancelled'
    `).get(appointmentDate, appointmentTime);

    if (existingAppointment) {
      return res.status(409).json({
        error: "That time slot is already booked. Please choose another time."
      });
    }

    const createBooking = db.transaction(() => {
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
          appointment_date,
          appointment_time,
          status
        )
        VALUES (?, ?, ?, ?, 'pending')
      `).run(
        customerResult.lastInsertRowid,
        Number(serviceId),
        appointmentDate,
        appointmentTime
      );

      return appointmentResult.lastInsertRowid;
    });

    const appointmentId = createBooking();

    return res.status(201).json({
      message: "Booking submitted successfully. Awaiting salon confirmation.",
      appointmentId,
      status: "pending"
    });
  } catch (error) {
    console.error("Booking error:", error);

    return res.status(500).json({
      error: "Could not save your booking. Please try again."
    });
  }
});

// OWNER: View appointments and private customer details.
app.get("/api/appointments", requireOwner, (req, res) => {
  try {
    const appointments = db.prepare(`
      SELECT
        appointments.id,
        customers.name AS customer_name,
        customers.phone AS customer_phone,
        customers.email AS customer_email,
        services.name AS service_name,
        services.price AS service_price,
        appointments.appointment_date,
        appointments.appointment_time,
        appointments.status
      FROM appointments
      JOIN customers
        ON appointments.customer_id = customers.id
      JOIN services
        ON appointments.service_id = services.id
      ORDER BY
        appointments.appointment_date,
        appointments.appointment_time
    `).all();

    return res.json(appointments);
  } catch (error) {
    console.error("Error loading appointments:", error);

    return res.status(500).json({
      error: "Could not load appointments."
    });
  }
});

// OWNER: Update appointment status.
app.patch("/api/appointments/:id", requireOwner, (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body ?? {};

    const allowedStatuses = [
      "pending",
      "confirmed",
      "cancelled"
    ];

    if (!Number.isInteger(id) || id < 1) {
      return res.status(400).json({
        error: "Invalid appointment ID."
      });
    }

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({
        error: "Invalid appointment status."
      });
    }

    const result = db.prepare(`
      UPDATE appointments
      SET status = ?
      WHERE id = ?
    `).run(status, id);

    if (result.changes === 0) {
      return res.status(404).json({
        error: "Appointment not found."
      });
    }

    return res.json({
      message: "Appointment status updated successfully.",
      id,
      status
    });
  } catch (error) {
    console.error("Error updating appointment:", error);

    return res.status(500).json({
      error: "Could not update appointment status."
    });
  }
});

// START BACKEND.
app.listen(PORT, () => {
  console.log(`SalonHub backend running at http://localhost:${PORT}`);
});