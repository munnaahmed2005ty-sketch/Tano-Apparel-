
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { promisify } = require("util");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");

fs.mkdirSync(DATA_DIR, { recursive: true });

if (!process.env.SESSION_SECRET ||
    process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

if (!process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD_HASH ||
    !/^\$2[aby]\$/.test(process.env.ADMIN_PASSWORD_HASH)) {
  throw new Error(
    "Set ADMIN_USERNAME and a valid bcrypt ADMIN_PASSWORD_HASH in .env."
  );
}

const STORE_NAME = process.env.STORE_NAME || "Dhaka Threads";
const STORE_PHONE = process.env.STORE_PHONE || "";
const BKASH_NUMBER = process.env.BKASH_NUMBER || "";
const NAGAD_NUMBER = process.env.NAGAD_NUMBER || "";
const SHIPPING_FEE = Math.max(
  0, Number(process.env.SHIPPING_FEE) || 80
);
const FREE_SHIPPING_THRESHOLD = Math.max(
  0, Number(process.env.FREE_SHIPPING_THRESHOLD) || 3000
);

const db = new sqlite3.Database(path.join(DATA_DIR, "store.sqlite"));
const dbRun = promisify(db.run.bind(db));
const dbGet = promisify(db.get.bind(db));
const dbAll = promisify(db.all.bind(db));

db.runAsync = dbRun;
db.getAsync = dbGet;
db.allAsync = dbAll;

app.disable("x-powered-by");
app.set("trust proxy", process.env.NODE_ENV === "production" ? 1 : false);
app.set("view engine", "ejs");
app.set("views", path.join(ROOT, "views"));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com",
        "https://cdn.tailwindcss.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests:
        process.env.NODE_ENV === "production" ? [] : null
    }
  }
}));

app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(ROOT, "public"), {
  dotfiles: "deny",
  index: false,
  maxAge: process.env.NODE_ENV === "production" ? "1d" : 0
}));

app.use(session({
  name: "fashion.sid",
  store: new SQLiteStore({
    db: "sessions.sqlite",
    dir: DATA_DIR,
    concurrentDB: true
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Session-backed CSRF protection for all POST requests.
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  res.locals.csrfToken = req.session.csrfToken;
  res.locals.storeName = STORE_NAME;
  res.locals.storePhone = STORE_PHONE;
  res.locals.bkashNumber = BKASH_NUMBER;
  res.locals.nagadNumber = NAGAD_NUMBER;
  res.locals.currentPath = req.path;
  res.locals.isAdmin = Boolean(req.session.admin);
  res.locals.cartCount = (req.session.cart || []).reduce(
    (sum, item) => sum + item.qty, 0
  );
  res.locals.notice = req.session.notice || null;
  delete req.session.notice;

  if (req.method === "POST") {
    const token = req.body && req.body._csrf;
    const expected = req.session.csrfToken;

    if (
      typeof token !== "string" ||
      typeof expected !== "string" ||
      token.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))
    ) {
      return res.status(403).send("Invalid or expired form token. Go back and reload the page.");
    }
  }

  next();
});

app.use((req, res, next) => {
  res.locals.formatMoney = (value) =>
    "৳" + Number(value || 0).toLocaleString("en-BD", {
      maximumFractionDigits: 2
    });
  next();
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: "Too many login attempts. Try again in 15 minutes."
});

function notice(req, message, type = "success") {
  req.session.notice = { message, type };
}

function isAdmin(req, res, next) {
  if (!req.session.admin) {
    notice(req, "Please log in to access the admin panel.", "error");
    return res.redirect("/admin/login");
  }
  next();
}

function cleanText(value, max = 200) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, max);
}

function validId(value) {
  return /^\d+$/.test(String(value)) && Number(value) > 0;
}

function validImageUrl(value) {
  if (!value) return true;
  try {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol);
  } catch {
    return false;
  }
}

function parseProduct(body) {
  const name = cleanText(body.name, 120);
  const description = cleanText(body.description, 2000);
  const category = cleanText(body.category, 60);
  const price = Number(body.price);
  const stock = Number(body.stock);
  const compareAt = body.compare_at === "" ? null : Number(body.compare_at);
  const image = cleanText(body.image, 1000);
  const sizes = cleanText(body.sizes, 150);
  const colors = cleanText(body.colors, 200);
  const active = body.active === "on" ? 1 : 0;

  if (!name || !description || !category) {
    throw new Error("Name, description and category are required.");
  }
  if (!Number.isFinite(price) || price < 0 || price > 10000000) {
    throw new Error("Enter a valid product price.");
  }
  if (!Number.isInteger(stock) || stock < 0 || stock > 1000000) {
    throw new Error("Stock must be a non-negative whole number.");
  }
  if (compareAt !== null &&
      (!Number.isFinite(compareAt) || compareAt < price)) {
    throw new Error("Original price must be at least the selling price.");
  }
  if (!validImageUrl(image)) {
    throw new Error("Image must be a valid HTTP or HTTPS URL.");
  }

  return {
    name,
    description,
    category,
    price: Math.round(price * 100) / 100,
    compare_at: compareAt === null ? null :
      Math.round(compareAt * 100) / 100,
    stock,
    image,
    sizes: sizes || "Free Size",
    colors: colors || "As shown",
    active
  };
}

async function initializeDatabase() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      price REAL NOT NULL CHECK(price >= 0),
      compare_at REAL,
      stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
      image TEXT NOT NULL DEFAULT '',
      sizes TEXT NOT NULL DEFAULT 'Free Size',
      colors TEXT NOT NULL DEFAULT 'As shown',
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      customer_name TEXT NOT NULL,
      phone TEXT NOT NULL,
      address TEXT NOT NULL,
      city TEXT NOT NULL,
      notes TEXT NOT NULL DEFAULT '',
      payment_method TEXT NOT NULL,
      trx_id TEXT NOT NULL DEFAULT '',
      items_json TEXT NOT NULL,
      subtotal REAL NOT NULL,
      shipping_fee REAL NOT NULL,
      total REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      payment_status TEXT NOT NULL DEFAULT 'Unverified',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const count = await dbGet("SELECT COUNT(*) AS count FROM products");
  if (count.count === 0) {
    const samples = [
      {
        name: "Classic Oversized T-Shirt",
        description: "A relaxed-fit everyday cotton tee, made for comfort and effortless streetwear styling.",
        category: "T-Shirts",
        price: 650,
        compare_at: 850,
        stock: 40,
        image: "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?auto=format&fit=crop&w=900&q=85",
        sizes: "S,M,L,XL,XXL",
        colors: "Black,White,Navy,Olive"
      },
      {
        name: "Premium Full Sleeve Tee",
        description: "A versatile long-sleeve essential for everyday wear and cooler evenings.",
        category: "T-Shirts",
        price: 790,
        compare_at: 990,
        stock: 30,
        image: "https://images.unsplash.com/photo-1503341504253-dff4815485f1?auto=format&fit=crop&w=900&q=85",
        sizes: "S,M,L,XL,XXL",
        colors: "Black,White,Grey"
      },
      {
        name: "Everyday Denim Jacket",
        description: "A timeless layering piece with a structured denim look.",
        category: "Jackets",
        price: 1850,
        compare_at: null,
        stock: 15,
        image: "https://images.unsplash.com/photo-1529139574466-a303027c1d8b?auto=format&fit=crop&w=900&q=85",
        sizes: "M,L,XL,XXL",
        colors: "Blue,Black"
      },
      {
        name: "Relaxed Fit Shirt",
        description: "An easy-to-style shirt for casual days and smart-casual occasions.",
        category: "Shirts",
        price: 1150,
        compare_at: null,
        stock: 24,
        image: "https://images.unsplash.com/photo-1598033129183-c4f50c736f10?auto=format&fit=crop&w=900&q=85",
        sizes: "S,M,L,XL",
        colors: "White,Blue,Black"
      },
      {
        name: "Minimal Everyday Hoodie",
        description: "A comfortable hoodie with a clean silhouette and an easy relaxed fit.",
        category: "Hoodies",
        price: 1450,
        compare_at: 1690,
        stock: 18,
        image: "https://images.unsplash.com/photo-1556821840-3a63f95609a7?auto=format&fit=crop&w=900&q=85",
        sizes: "M,L,XL,XXL",
        colors: "Black,Grey,Olive"
      },
      {
        name: "Essential Cotton Polo",
        description: "A clean polo shirt for everyday comfort and a slightly smarter look.",
        category: "Polo",
        price: 890,
        compare_at: null,
        stock: 32,
        image: "https://images.unsplash.com/photo-1625910513413-5fc3c0a6a5b7?auto=format&fit=crop&w=900&q=85",
        sizes: "S,M,L,XL,XXL",
        colors: "Navy,White,Maroon"
      }
    ];

    for (const p of samples) {
      await dbRun(
        `INSERT INTO products
        (name,description,category,price,compare_at,stock,image,sizes,colors)
        VALUES (?,?,?,?,?,?,?,?,?)`,
        [p.name, p.description, p.category, p.price, p.compare_at,
          p.stock, p.image, p.sizes, p.colors]
      );
    }
  }
}

async function getCart(req) {
  const cart = req.session.cart || [];
  const validItems = [];
  let subtotal = 0;

  for (const item of cart) {
    const product = await dbGet(
      "SELECT * FROM products WHERE id = ? AND active = 1",
      [item.productId]
    );
    if (!product || product.stock < 1) continue;

    const qty = Math.min(
      Math.max(1, Math.floor(Number(item.qty) || 1)),
      product.stock
    );

    const lineTotal = Math.round(product.price * qty * 100) / 100;
    subtotal += lineTotal;
    validItems.push({
      product,
      qty,
      size: item.size || product.sizes.split(",")[0],
      color: item.color || product.colors.split(",")[0],
      lineTotal
    });
  }

  req.session.cart = validItems.map(item => ({
    productId: item.product.id,
    qty: item.qty,
    size: item.size,
    color: item.color
  }));

  subtotal = Math.round(subtotal * 100) / 100;
  const shippingFee = subtotal === 0 ||
    subtotal >= FREE_SHIPPING_THRESHOLD ? 0 : SHIPPING_FEE;

  return {
    items: validItems,
    subtotal,
    shippingFee,
    total: Math.round((subtotal + shippingFee) * 100) / 100
  };
}

app.get("/", async (req, res, next) => {
  try {
    const products = await dbAll(
      "SELECT * FROM products WHERE active = 1 ORDER BY id DESC LIMIT 8"
    );
    const categories = await dbAll(
      "SELECT category, COUNT(*) AS count FROM products WHERE active=1 GROUP BY category ORDER BY category"
    );
    res.render("index", { products, categories });
  } catch (err) {
    next(err);
  }
});

app.get("/shop", async (req, res, next) => {
  try {
    const search = cleanText(req.query.q, 100);
    const category = cleanText(req.query.category, 60);
    const sort = cleanText(req.query.sort, 20);
    const orderBy = {
      newest: "id DESC",
      price_low: "price ASC",
      price_high: "price DESC",
      name: "name COLLATE NOCASE ASC"
    }[sort] || "id DESC";

    const conditions = ["active = 1"];
    const params = [];

    if (search) {
      conditions.push("(name LIKE ? OR description LIKE ?)");
      params.push(`%${search}%`, `%${search}%`);
    }
    if (category) {
      conditions.push("category = ?");
      params.push(category);
    }

    const products = await dbAll(
      `SELECT * FROM products WHERE ${conditions.join(" AND ")} ORDER BY ${orderBy}`,
      params
    );
    const categories = await dbAll(
      "SELECT DISTINCT category FROM products WHERE active=1 ORDER BY category"
    );

    res.render("shop", { products, categories, search, category, sort });
  } catch (err) {
    next(err);
  }
});

app.get("/product/:id", async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.status(404).send("Product not found.");
    const product = await dbGet(
      "SELECT * FROM products WHERE id = ? AND active = 1",
      [Number(req.params.id)]
    );
    if (!product) return res.status(404).send("Product not found.");

    const related = await dbAll(
      "SELECT * FROM products WHERE active=1 AND category=? AND id<>? LIMIT 4",
      [product.category, product.id]
    );

    res.render("product-detail", { product, related });
  } catch (err) {
    next(err);
  }
});

app.post("/cart/add", async (req, res, next) => {
  try {
    const id = Number(req.body.product_id);
    const qty = Number(req.body.quantity);
    const product = await dbGet(
      "SELECT * FROM products WHERE id=? AND active=1",
      [id]
    );

    if (!product) {
      notice(req, "That product is unavailable.", "error");
      return res.redirect("/shop");
    }
    if (!Number.isInteger(qty) || qty < 1 || qty > 20) {
      notice(req, "Choose a quantity between 1 and 20.", "error");
      return res.redirect(`/product/${id}`);
    }
    if (product.stock < qty) {
      notice(req, "Not enough stock for that quantity.", "error");
      return res.redirect(`/product/${id}`);
    }

    const sizes = product.sizes.split(",").map(s => s.trim());
    const colors = product.colors.split(",").map(c => c.trim());
    const size = cleanText(req.body.size, 30);
    const color = cleanText(req.body.color, 40);

    if (!sizes.includes(size) || !colors.includes(color)) {
      notice(req, "Please choose a valid size and color.", "error");
      return res.redirect(`/product/${id}`);
    }

    const cart = req.session.cart || [];
    const existing = cart.find(item =>
      item.productId === id && item.size === size && item.color === color
    );

    if (existing) {
      if (existing.qty + qty > product.stock ||
          existing.qty + qty > 20) {
        notice(req, "That quantity exceeds available stock.", "error");
        return res.redirect("/cart");
      }
      existing.qty += qty;
    } else {
      cart.push({ productId: id, qty, size, color });
    }

    req.session.cart = cart;
    notice(req, `${product.name} added to your cart.`);
    res.redirect(req.body.buy_now === "1" ? "/checkout" : "/cart");
  } catch (err) {
    next(err);
  }
});

app.get("/cart", async (req, res, next) => {
  try {
    const cart = await getCart(req);
    res.render("cart", { cart });
  } catch (err) {
    next(err);
  }
});

app.post("/cart/update", async (req, res, next) => {
  try {
    const id = Number(req.body.product_id);
    const qty = Number(req.body.quantity);
    const size = cleanText(req.body.size, 30);
    const color = cleanText(req.body.color, 40);
    const product = await dbGet(
      "SELECT * FROM products WHERE id=? AND active=1",
      [id]
    );

    if (!product) {
      notice(req, "Product no longer available.", "error");
      return res.redirect("/cart");
    }

    if (!Number.isInteger(qty) || qty < 1 || qty > 20 ||
        qty > product.stock ||
        !product.sizes.split(",").map(s => s.trim()).includes(size) ||
        !product.colors.split(",").map(c => c.trim()).includes(color)) {
      notice(req, "Invalid quantity, size, or color.", "error");
      return res.redirect("/cart");
    }

    const cart = req.session.cart || [];
    const item = cart.find(x =>
      x.productId === id && x.size === size && x.color === color
    );

    if (item) item.qty = qty;
    req.session.cart = cart;
    notice(req, "Cart updated.");
    res.redirect("/cart");
  } catch (err) {
    next(err);
  }
});

app.post("/cart/remove", (req, res) => {
  const id = Number(req.body.product_id);
  const size = cleanText(req.body.size, 30);
  const color = cleanText(req.body.color, 40);

  req.session.cart = (req.session.cart || []).filter(item =>
    !(item.productId === id && item.size === size && item.color === color)
  );

  notice(req, "Item removed from cart.");
  res.redirect("/cart");
});

app.get("/checkout", async (req, res, next) => {
  try {
    const cart = await getCart(req);
    if (!cart.items.length) {
      notice(req, "Add a product before checking out.", "error");
      return res.redirect("/shop");
    }
    res.render("checkout", { cart });
  } catch (err) {
    next(err);
  }
});

app.post("/checkout", async (req, res, next) => {
  try {
    const cart = await getCart(req);
    if (!cart.items.length) {
      notice(req, "Your cart is empty.", "error");
      return res.redirect("/shop");
    }

    const customerName = cleanText(req.body.name, 100);
    const phone = cleanText(req.body.phone, 20).replace(/[\s-]/g, "");
    const address = cleanText(req.body.address, 500);
    const city = cleanText(req.body.city, 100);
    const notes = cleanText(req.body.notes, 500);
    const paymentMethod = cleanText(req.body.payment_method, 20);
    const trxId = cleanText(req.body.trx_id, 100);

    if (customerName.length < 2 ||
        !/^(?:\+?8801|01)[3-9]\d{8}$/.test(phone) ||
        address.length < 8 ||
        city.length < 2 ||
        !["cod", "bkash", "nagad"].includes(paymentMethod)) {
      notice(req, "Check your name, Bangladeshi phone number, address, city and payment method.", "error");
      return res.redirect("/checkout");
    }

    if (paymentMethod !== "cod" &&
        !/^[A-Za-z0-9-]{5,100}$/.test(trxId)) {
      notice(req, "Enter a valid transaction ID for mobile payment.", "error");
      return res.redirect("/checkout");
    }

    // Re-check stock and prices immediately before saving the order.
    for (const item of cart.items) {
      const fresh = await dbGet(
        "SELECT stock, price, active FROM products WHERE id=?",
        [item.product.id]
      );
      if (!fresh || !fresh.active || fresh.stock < item.qty ||
          fresh.price !== item.product.price) {
        notice(req, "A product's stock or price changed. Please review your cart.", "error");
        return res.redirect("/cart");
      }
    }

    const itemsJson = JSON.stringify(cart.items.map(item => ({
      product_id: item.product.id,
      name: item.product.name,
      price: item.product.price,
      qty: item.qty,
      size: item.size,
      color: item.color,
      line_total: item.lineTotal
    })));

    await dbRun("BEGIN IMMEDIATE TRANSACTION");

    try {
      // Conditional stock updates prevent overselling under concurrent requests.
      for (const item of cart.items) {
        const update = await new Promise((resolve, reject) => {
          db.run(
            "UPDATE products SET stock=stock-? WHERE id=? AND active=1 AND stock>=?",
            [item.qty, item.product.id, item.qty],
            function (err) {
              if (err) return reject(err);
              resolve(this.changes);
            }
          );
        });

        if (update !== 1) throw new Error("STOCK_CHANGED");
      }

      const orderResult = await new Promise((resolve, reject) => {
        db.run(
          `INSERT INTO orders
          (customer_name,phone,address,city,notes,payment_method,trx_id,
           items_json,subtotal,shipping_fee,total,status,payment_status)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,'Pending',?)`,
          [
            customerName, phone, address, city, notes, paymentMethod,
            paymentMethod === "cod" ? "" : trxId,
            itemsJson, cart.subtotal, cart.shippingFee, cart.total,
            paymentMethod === "cod" ? "Not required" : "Unverified"
          ],
          function (err) {
            if (err) return reject(err);
            resolve(this.lastID);
          }
        );
      });

      await dbRun("COMMIT");
      req.session.cart = [];
      req.session.lastOrderId = orderResult;
      return res.redirect(`/order-success/${orderResult}`);
    } catch (err) {
      await dbRun("ROLLBACK");
      if (err.message === "STOCK_CHANGED") {
        notice(req, "Stock changed while you were checking out. Please review your cart.", "error");
        return res.redirect("/cart");
      }
      throw err;
    }
  } catch (err) {
    next(err);
  }
});

app.get("/order-success/:id", (req, res) => {
  const id = Number(req.params.id);
  if (!validId(id) || req.session.lastOrderId !== id) {
    return res.status(404).send("Order confirmation not found.");
  }
  req.session.lastOrderId = null;
  res.render("order-success", { orderId: id });
});

app.get("/admin/login", (req, res) => {
  if (req.session.admin) return res.redirect("/admin");
  res.render("admin/login");
});

app.post("/admin/login", loginLimiter, async (req, res, next) => {
  try {
    const username = cleanText(req.body.username, 100);
    const password = typeof req.body.password === "string"
      ? req.body.password.slice(0, 200) : "";

    const usernameOk = username === process.env.ADMIN_USERNAME;
    const passwordOk = await bcrypt.compare(
      password,
      process.env.ADMIN_PASSWORD_HASH
    );

    if (!usernameOk || !passwordOk) {
      notice(req, "Invalid username or password.", "error");
      return res.redirect("/admin/login");
    }

    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.admin = true;
      req.session.csrfToken = crypto.randomBytes(32).toString("hex");
      req.session.notice = {
        message: "Welcome to your dashboard.",
        type: "success"
      };
      res.redirect("/admin");
    });
  } catch (err) {
    next(err);
  }
});

app.post("/admin/logout", isAdmin, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("fashion.sid");
    res.redirect("/admin/login");
  });
});

app.get("/admin", isAdmin, async (req, res, next) => {
  try {
    const products = await dbAll(
      "SELECT * FROM products ORDER BY id DESC"
    );
    const orders = await dbAll(
      "SELECT * FROM orders ORDER BY id DESC LIMIT 200"
    );

    for (const order of orders) {
      try {
        order.items = JSON.parse(order.items_json);
      } catch {
        order.items = [];
      }
    }

    res.render("admin/dashboard", {
      products,
      orders,
      editingProduct: null
    });
  } catch (err) {
    next(err);
  }
});

app.get("/admin/products/:id/edit", isAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.redirect("/admin");
    const editingProduct = await dbGet(
      "SELECT * FROM products WHERE id=?",
      [Number(req.params.id)]
    );
    if (!editingProduct) {
      notice(req, "Product not found.", "error");
      return res.redirect("/admin");
    }

    const products = await dbAll("SELECT * FROM products ORDER BY id DESC");
    const orders = await dbAll("SELECT * FROM orders ORDER BY id DESC LIMIT 200");
    for (const order of orders) {
      try { order.items = JSON.parse(order.items_json); }
      catch { order.items = []; }
    }

    res.render("admin/dashboard", { products, orders, editingProduct });
  } catch (err) {
    next(err);
  }
});

app.post("/admin/products", isAdmin, async (req, res, next) => {
  try {
    const p = parseProduct(req.body);
    await dbRun(
      `INSERT INTO products
      (name,description,category,price,compare_at,stock,image,sizes,colors,active)
      VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [p.name, p.description, p.category, p.price, p.compare_at,
        p.stock, p.image, p.sizes, p.colors, p.active]
    );
    notice(req, "Product created.");
    res.redirect("/admin");
  } catch (err) {
    if (err.message && !err.code) {
      notice(req, err.message, "error");
      return res.redirect("/admin");
    }
    next(err);
  }
});

app.post("/admin/products/:id/edit", isAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.redirect("/admin");
    const p = parseProduct(req.body);
    const result = await dbRun(
      `UPDATE products SET
      name=?,description=?,category=?,price=?,compare_at=?,stock=?,
      image=?,sizes=?,colors=?,active=? WHERE id=?`,
      [p.name, p.description, p.category, p.price, p.compare_at,
        p.stock, p.image, p.sizes, p.colors, p.active,
        Number(req.params.id)]
    );

    notice(req, "Product updated.");
    res.redirect("/admin");
  } catch (err) {
    if (err.message && !err.code) {
      notice(req, err.message, "error");
      return res.redirect("/admin/products/" + req.params.id + "/edit");
    }
    next(err);
  }
});

app.post("/admin/products/:id/delete", isAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.redirect("/admin");
    // Soft-delete so historical orders remain meaningful.
    await dbRun(
      "UPDATE products SET active=0 WHERE id=?",
      [Number(req.params.id)]
    );
    notice(req, "Product removed from the storefront.");
    res.redirect("/admin");
  } catch (err) {
    next(err);
  }
});

app.post("/admin/orders/:id/status", isAdmin, async (req, res, next) => {
  try {
    if (!validId(req.params.id)) return res.redirect("/admin");

    const status = cleanText(req.body.status, 30);
    const paymentStatus = cleanText(req.body.payment_status, 30);

    const validStatuses = [
      "Pending", "Confirmed", "Processing", "Shipped",
      "Delivered", "Cancelled"
    ];
    const validPaymentStatuses = [
      "Unverified", "Verified", "Rejected", "Not required"
    ];

    if (!validStatuses.includes(status) ||
        !validPaymentStatuses.includes(paymentStatus)) {
      notice(req, "Invalid order or payment status.", "error");
      return res.redirect("/admin");
    }

    const order = await dbGet(
      "SELECT payment_method FROM orders WHERE id=?",
      [Number(req.params.id)]
    );

    if (!order) {
      notice(req, "Order not found.", "error");
      return res.redirect("/admin");
    }

    if (order.payment_method === "cod" &&
        paymentStatus !== "Not required") {
      notice(req, "COD orders do not use mobile payment verification.", "error");
      return res.redirect("/admin");
    }
    if (order.payment_method !== "cod" &&
        paymentStatus === "Not required") {
      notice(req, "Mobile payments must be verified or rejected.", "error");
      return res.redirect("/admin");
    }

    await dbRun(
      "UPDATE orders SET status=?,payment_status=? WHERE id=?",
      [status, paymentStatus, Number(req.params.id)]
    );
    notice(req, "Order updated.");
    res.redirect("/admin");
  } catch (err) {
    next(err);
  }
});

// Friendly not-found and error handlers.
app.use((req, res) => {
  res.status(404).send("Page not found.");
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).send(
    process.env.NODE_ENV === "production"
      ? "Something went wrong. Please try again."
      : `Application error: ${cleanText(err.message, 300)}`
  );
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`${STORE_NAME} running at http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
