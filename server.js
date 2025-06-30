const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const db = new sqlite3.Database("./users.db");

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "mySecretKey",
    resave: false,
    saveUninitialized: false,
  })
);

// Create users table
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  password TEXT
)`);

// Routes
app.get("/", (req, res) => {
  if (req.session.username) {
    res.send(`Welcome ${req.session.username}! <a href="/logout">Logout</a>`);
  } else {
    res.send('<a href="/login">Login</a> or <a href="/register">Register</a>');
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
    if (err) return res.send("Error registering user.");
    res.redirect("/login");
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.send("User not found.");
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.username = username;
      res.redirect("/");
    } else {
      res.send("Incorrect password.");
    }
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
