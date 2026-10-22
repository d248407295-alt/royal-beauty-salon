import fs from "node:fs";
import bcrypt from "bcryptjs";
import readline from "node:readline/promises";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const email = (
  await rl.question("Enter the salon owner's email: ")
).trim().toLowerCase();

if (!email || !email.includes("@")) {
  console.log("Please enter a valid email address.");
  rl.close();
  process.exit(1);
}

rl.close();

if (!process.stdin.isTTY) {
  console.log("Run this script in a normal terminal.");
  process.exit(1);
}

process.stdout.write("Create a strong owner password: ");

const password = await new Promise((resolve) => {
  let value = "";

  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");

  process.stdin.on("data", function handleKey(key) {
    if (key === "\u0003") {
      process.stdout.write("\nCancelled.\n");
      process.exit(1);
    }

    if (key === "\r" || key === "\n") {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener("data", handleKey);
      process.stdout.write("\n");
      resolve(value);
    } else if (key === "\u007f" || key === "\b") {
      value = value.slice(0, -1);
    } else if (key >= " ") {
      value += key;
    }
  });
});

if (password.length < 12) {
  console.log("Use a password with at least 12 characters.");
  process.exit(1);
}

const envPath = ".env";

if (!fs.existsSync(envPath)) {
  console.log(".env file not found. No changes made.");
  process.exit(1);
}

const currentEnv = fs.readFileSync(envPath, "utf8");

if (!/^JWT_SECRET=.+/m.test(currentEnv)) {
  console.log("JWT_SECRET is missing. No changes made.");
  process.exit(1);
}

const hash = await bcrypt.hash(password, 12);

const cleanedEnv = currentEnv
  .replace(/^OWNER_EMAIL=.*\n?/m, "")
  .replace(/^OWNER_PASSWORD_HASH=.*\n?/m, "")
  .trimEnd();

fs.writeFileSync(
  envPath,
  `${cleanedEnv}\nOWNER_EMAIL=${email}\nOWNER_PASSWORD_HASH=${hash}\n`,
  { mode: 0o600 }
);

fs.chmodSync(envPath, 0o600);

console.log("Owner login settings saved securely.");
console.log("Your password was not saved as plain text.");

