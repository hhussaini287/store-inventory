const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express(); // ✅ MUST COME BEFORE app.use()

/* ================== CONFIG ================== */
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI; // from Render env
const JWT_SECRET = process.env.JWT_SECRET || "secret123";

/* ================== MIDDLEWARE ================== */
app.use(cors({
  origin: "*"
}));

app.use(express.json());

/* ================== DATABASE ================== */
mongoose.connect(MONGO_URI)
.then(() => console.log("MongoDB connected"))
.catch(err => console.log(err));

/* ================== MODELS ================== */
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  firstName: String,
  lastName: String,
  email: String,
  phone: String
});

const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,
  qty: Number,
  userId: String
});

const User = mongoose.model("User", UserSchema);
const Product = mongoose.model("Product", ProductSchema);

/* ================== AUTH MIDDLEWARE ================== */
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.status(401).send("No token");

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).send("Invalid token");
  }
}

/* ================== ROUTES ================== */

/* REGISTER */
app.post("/register", async (req, res) => {
  try {
    const { username, password, firstName, lastName, email, phone } = req.body;

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).send("User already exists");

    const hashed = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      password: hashed,
      firstName,
      lastName,
      email,
      phone
    });

    await user.save();

    res.send("User registered");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

/* LOGIN */
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).send("Invalid credentials");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).send("Invalid credentials");

    const token = jwt.sign({ id: user._id }, JWT_SECRET);

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

/* GET PRODUCTS */
app.get("/products", auth, async (req, res) => {
  try {
    const products = await Product.find({ userId: req.userId });
    res.json(products);
  } catch {
    res.status(500).send("Error fetching products");
  }
});

/* ADD PRODUCT */
app.post("/products", auth, async (req, res) => {
  try {
    const { name, price, qty } = req.body;

    const product = new Product({
      name,
      price,
      qty,
      userId: req.userId
    });

    await product.save();

    res.send("Product added");
  } catch {
    res.status(500).send("Error saving product");
  }
});

/* ================== SERVER ================== */
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
