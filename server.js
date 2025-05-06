require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const path = require("path");

const app = express();
const client = new MongoClient(process.env.MONGODB_URI);

// connecting to DB
let userCollection;
async function connectToDatabase() {
  try {
    await client.connect();
    const db = client.db(process.env.MONGODB_DB_NAME);
    userCollection = db.collection("users");
    console.log("Connected to DB");
  } catch (err) {
    console.error("DB connection error:", err);
    process.exit(1);
  }
}
connectToDatabase();

//setting ejs as template, parsing incoming data, and serving static files
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

//setting up session and saving it to mongo 
app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      dbName: process.env.MONGODB_DB_NAME,
      collectionName: "sessions",
      ttl: 60 * 60,
    }),
    resave: false,
    saveUninitialized: false,
  })
);

//middleware to protect routes
function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/");
  next();
}

//listener for the home page and renders the index page
app.get("/", (req, res) => {
  res.render("index", { user: req.session.user });
});

//listener for the signup page and renders the signup page
app.get("/signup", (req, res) => {
  res.render("signup");
});

//validated signup data, hashes password, adds user to db, and redirects to members page
app.post("/signup", async (req, res) => {
  const schema = Joi.object({
    name: Joi.string()
      .required()
      .messages({ "string.empty": "Name is required" }),
    email: Joi.string()
      .email()
      .required()
      .messages({ "string.empty": "Email is required" }),
    password: Joi.string()
      .required()
      .messages({ "string.empty": "Password is required" }),
  });

  const { error } = schema.validate(req.body);
  if (error)
    return res.send(
      `${error.details[0].message} <br /> <br /> <a href="/signup">Try again</a>`
    );

  const hashed = await bcrypt.hash(req.body.password, 10);

  await userCollection.insertOne({
    name: req.body.name,
    email: req.body.email,
    password: hashed,
  });

  req.session.user = { name: req.body.name };
  res.redirect("/members");
});

//listener for the login page and renders the login page
app.get("/login", (req, res) => {
  res.render("login");
});

//validates login data, looks up user by email on db, compares pw with hashed pw, and redirects to members page
app.post("/login", async (req, res) => {
  const schema = Joi.object({
    email: Joi.string()
      .email()
      .required()
      .messages({ "string.empty": "Email is required" }),
    password: Joi.string()
      .required()
      .messages({ "string.empty": "Password is required" }),
  });

  const { error } = schema.validate(req.body);
  if (error)
    return res.send(
      `${error.details[0].message} <a href="/login">Try again</a>`
    );

  const user = await userCollection.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return res.send("Invalid email/password combination. <br /> <a href='/login'>Try again</a>");
  }

  req.session.user = { name: user.name };
  res.redirect("/members");
});

//serves up random image on members page
app.get("/members", requireLogin, (req, res) => {
  const images = ["react.png", "nextjs.png", "ejs.png"];
  const img = images[Math.floor(Math.random() * images.length)];
  res.render("members", { name: req.session.user.name, image: img });
});

//logs user out and destyoys the session
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

//render for 404 page
app.use((req, res) => {
  res.status(404).render("404");
});

//server listener
app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});
