require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const PORT = process.env.Port || 3000;

app.listen(PORT, () => console.log("Server running on port " + PORT));

const app = express();
app.use(express.json());
app.use(cors({
  origin: "https://storewebinventory.netlify.app"
}))

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

const User = mongoose.model("User", {
  username: String,
  password: String
});

const Product = mongoose.model("Product", {
  name: String,
  price: Number,
  qty: Number,
  userId: String
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });

  await user.save();
  res.json({ message: "User created" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/products", auth, async (req, res) => {
  const product = new Product({
    ...req.body,
    userId: req.user.id
  });

  await product.save();
  res.json(product);
});

app.get("/products", auth, async (req, res) => {
  const products = await Product.find({ userId: req.user.id });
  res.json(products);
});

app.put("/products/:id", auth, async (req, res) => {
  const updated = await Product.findByIdAndUpdate(
    req.params.id,
    req.body,
    { new: true }
  );
  res.json(updated);
});

app.delete("/products/:id", auth, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: "Deleted" });
});

app.listen(process.env.PORT, () =>
  console.log("Server running on port " + process.env.PORT)
);
