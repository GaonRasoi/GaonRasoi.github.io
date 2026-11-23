/**
 * ============================================================================
 * GAON RASOI - HYPERLOCAL VILLAGE FOOD DELIVERY BACKEND (Express + MongoDB)
 * ============================================================================
 * Audited & Production-Ready for Render Free Tier + MongoDB Atlas Free Tier.
 * Modules:
 *  1. Public Store, Veg/Non-Veg & Stock-Aware Menu, Coupon Validation, COD Orders
 *  2. Admin Auth (Timing-Safe Password + Stateless HMAC Token + Rate Limiter)
 *  3. Live Orders + Manual Phone Orders + Rider Assignment + Cancel/Admin Notes
 *  4. Delivery Rider Management + Cash vs UPI COD Reconciliation & Settlement
 *  5. Menu, Making Cost Margin & Optional Auto-Decrement Stock Counter
 *  6. IST Profit Analytics, Daily Shop Expenses & Top-Selling Items
 *  7. Customers CRM Directory, Promo Coupons, Store Settings & Blocked Numbers
 */

require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 5000;

// ----------------------------------------------------------------------------
// 1. ENVIRONMENT & SECURITY HELPERS
// ----------------------------------------------------------------------------

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean)
  .map((entry) => {
    try {
      return new URL(entry).origin;
    } catch {
      return entry.replace(/\/+$/, '');
    }
  });

app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

app.use(express.json({ limit: '150kb' }));

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.length === 0) {
        if (/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
          return callback(null, true);
        }
        return callback(new Error('CORS blocked: ALLOWED_ORIGIN is not configured on server.'));
      }
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

function normalizeIndianPhone(raw) {
  if (typeof raw !== 'string') return '';
  let digits = raw.replace(/\D/g, '');
  if (digits.length === 12 && digits.startsWith('91')) {
    digits = digits.slice(2);
  } else if (digits.length === 11 && digits.startsWith('0')) {
    digits = digits.slice(1);
  }
  return /^[6-9]\d{9}$/.test(digits) ? digits : '';
}

function safeCompareStrings(a, b) {
  const hashA = crypto.createHash('sha256').update(String(a)).digest();
  const hashB = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

function getTokenSecret() {
  if (process.env.TOKEN_SECRET) return process.env.TOKEN_SECRET;
  const pwd = process.env.ADMIN_PASSWORD || '';
  return crypto.createHash('sha256').update(`gaon-rasoi-secret:${pwd}`).digest('hex');
}

function createAdminToken() {
  const payload = {
    role: 'admin',
    iat: Date.now(),
    exp: Date.now() + 24 * 60 * 60 * 1000,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto
    .createHmac('sha256', getTokenSecret())
    .update(payloadB64)
    .digest('base64url');
  return `${payloadB64}.${signature}`;
}

function verifyAdminToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;

  const expectedSig = crypto
    .createHmac('sha256', getTokenSecret())
    .update(payloadB64)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    if (payload.role !== 'admin') return null;
    return payload;
  } catch {
    return null;
  }
}

const loginAttempts = new Map();
function pruneLoginAttempts() {
  if (loginAttempts.size <= 500) return;
  const now = Date.now();
  for (const [ip, rec] of loginAttempts.entries()) {
    if (now > rec.resetAt) loginAttempts.delete(ip);
  }
}
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record || now > record.resetAt) return { allowed: true };
  if (record.count >= 10) {
    return { allowed: false, retryAfterSec: Math.ceil((record.resetAt - now) / 1000) };
  }
  return { allowed: true };
}
function recordFailedLogin(ip) {
  pruneLoginAttempts();
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const record = loginAttempts.get(ip);
  if (!record || now > record.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + windowMs });
  } else {
    record.count += 1;
  }
}
function clearFailedLogins(ip) {
  loginAttempts.delete(ip);
}

function createRateLimiter({ max, windowMs, errorMessage }) {
  const hits = new Map();
  return function rateLimiter(req, res, next) {
    const now = Date.now();
    if (hits.size > 1000) {
      for (const [k, rec] of hits.entries()) {
        if (now > rec.resetAt) hits.delete(k);
      }
    }
    const key = req.ip || 'unknown';
    const rec = hits.get(key);
    if (!rec || now > rec.resetAt) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (rec.count >= max) {
      return res.status(429).json({
        code: 'RATE_LIMITED',
        error: errorMessage || 'Too many requests. Please wait a moment and try again.',
      });
    }
    rec.count += 1;
    return next();
  };
}

const orderCreateLimiter = createRateLimiter({
  max: 15,
  windowMs: 10 * 60 * 1000,
  errorMessage: 'Too many orders placed from this network. Please wait a few minutes.',
});
const couponValidateLimiter = createRateLimiter({
  max: 45,
  windowMs: 5 * 60 * 1000,
  errorMessage: 'Too many coupon checks. Please wait a moment.',
});
const orderLookupLimiter = createRateLimiter({
  max: 60,
  windowMs: 5 * 60 * 1000,
  errorMessage: 'Too many order lookup requests. Please wait a moment.',
});
const orderCancelLimiter = createRateLimiter({
  max: 20,
  windowMs: 10 * 60 * 1000,
  errorMessage: 'Too many cancel attempts. Please wait a moment.',
});

function requireAdmin(req, res, next) {
  if (!process.env.ADMIN_PASSWORD) {
    return res.status(503).json({ error: 'ADMIN_PASSWORD is not configured on server.' });
  }
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const payload = verifyAdminToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired admin session.' });
  }
  req.admin = payload;
  next();
}

function validateObjectId(req, res, next) {
  if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
    return res.status(400).json({ error: 'Invalid resource ID.' });
  }
  next();
}

// ----------------------------------------------------------------------------
// 2. MONGOOSE SCHEMAS & MODELS
// ----------------------------------------------------------------------------

const menuItemSchema = new mongoose.Schema(
  {
    nameHi: { type: String, required: true, trim: true },
    nameEn: { type: String, required: true, trim: true },
    descHi: { type: String, default: '', trim: true },
    descEn: { type: String, default: '', trim: true },
    category: { type: String, default: 'Snacks', trim: true },
    sellingPrice: { type: Number, required: true, min: 0 },
    makingCost: { type: Number, required: true, min: 0 },
    imageUrl: { type: String, default: '', trim: true },
    inStock: { type: Boolean, default: true },
    stockCount: { type: Number, default: null, min: 0 }, // null = unlimited, integer = auto-decrement
    isVeg: { type: Boolean, default: true },
    isPopular: { type: Boolean, default: false },
    sortOrder: { type: Number, default: 0 },
  },
  { timestamps: true }
);

const orderItemSchema = new mongoose.Schema(
  {
    menuItemId: { type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem', required: true },
    nameHi: { type: String, required: true },
    nameEn: { type: String, required: true },
    quantity: { type: Number, required: true, min: 1 },
    sellingPrice: { type: Number, required: true, min: 0 },
    makingCost: { type: Number, required: true, min: 0 },
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    orderNumber: { type: String, required: true, unique: true },
    customerName: { type: String, required: true, trim: true, maxlength: 100 },
    phone: { type: String, required: true, match: /^[6-9]\d{9}$/ },
    address: { type: String, required: true, trim: true, maxlength: 300 },
    customerNote: { type: String, default: '', trim: true, maxlength: 200 },
    gpsLocation: {
      lat: { type: Number, default: null },
      lng: { type: Number, default: null },
      mapLink: { type: String, default: '' },
    },
    items: { type: [orderItemSchema], required: true, validate: (v) => v.length > 0 },
    subtotal: { type: Number, required: true, min: 0 },
    discountAmount: { type: Number, default: 0, min: 0 },
    couponCode: { type: String, default: '', trim: true },
    deliveryCharge: { type: Number, required: true, min: 0 },
    totalAmount: { type: Number, required: true, min: 0 },
    totalMakingCost: { type: Number, required: true, min: 0 },
    paymentMethod: { type: String, enum: ['COD'], default: 'COD' },
    paymentCollectedMode: { type: String, enum: ['Pending', 'Cash', 'UPI'], default: 'Pending' },
    assignedRider: {
      riderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Rider', default: null },
      name: { type: String, default: '' },
      phone: { type: String, default: '' },
    },
    riderCashSettled: { type: Boolean, default: false },
    source: { type: String, enum: ['Website', 'Phone'], default: 'Website' },
    adminNote: { type: String, default: '', trim: true, maxlength: 250 },
    cancelDeadlineAt: { type: Date, default: null },
    cancelledBy: { type: String, enum: ['', 'Customer', 'Admin'], default: '' },
    cancelledAt: { type: Date, default: null },
    hiddenByCustomer: { type: Boolean, default: false },
    customerHiddenAt: { type: Date, default: null },
    status: {
      type: String,
      enum: ['Pending', 'Cooking', 'Out for Delivery', 'Delivered', 'Cancelled'],
      default: 'Pending',
    },
    statusSchedule: {
      cookingAt: { type: Date, default: null },
      outForDeliveryAt: { type: Date, default: null },
      deliveredAt: { type: Date, default: null },
      etaEndsAt: { type: Date, default: null },
      noteHi: { type: String, default: '', trim: true, maxlength: 140 },
      noteEn: { type: String, default: '', trim: true, maxlength: 140 },
      updatedAt: { type: Date, default: null },
    },
  },
  { timestamps: true }
);

const storeSettingsSchema = new mongoose.Schema(
  {
    key: { type: String, default: 'default', unique: true },
    shopNameHi: { type: String, default: 'गाँव रसोई' },
    shopNameEn: { type: String, default: 'Gaon Rasoi' },
    isOpen: { type: Boolean, default: true },
    deliveryCharge: { type: Number, default: 15, min: 0 },
    freeDeliveryAbove: { type: Number, default: 199, min: 0 },
    minOrderAmount: { type: Number, default: 60, min: 0 },
    deliveryRadiusKm: { type: Number, default: 2, min: 0.5 },
    openHoursHi: { type: String, default: 'सुबह 9:00 बजे से रात 9:30 बजे तक' },
    openHoursEn: { type: String, default: '9:00 AM – 9:30 PM' },
    supportPhone: { type: String, default: '', trim: true },
    upiId: { type: String, default: '', trim: true },
    announcementHi: { type: String, default: '', trim: true },
    announcementEn: { type: String, default: '', trim: true },
    timerTitleHi: { type: String, default: '', trim: true },
    timerTitleEn: { type: String, default: '', trim: true },
    timerEndsAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const blockedNumberSchema = new mongoose.Schema(
  {
    phone: { type: String, required: true, unique: true, match: /^[6-9]\d{9}$/ },
    reason: { type: String, default: 'Blocked by Admin', trim: true },
    blockedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const couponSchema = new mongoose.Schema(
  {
    code: { type: String, required: true, unique: true, uppercase: true, trim: true },
    titleHi: { type: String, default: '', trim: true, maxlength: 80 },
    titleEn: { type: String, default: '', trim: true, maxlength: 80 },
    applyTarget: { type: String, enum: ['ITEMS', 'FREE_DELIVERY', 'BOTH'], default: 'ITEMS' },
    discountType: { type: String, enum: ['FLAT', 'PERCENT', 'FREE_DELIVERY'], required: true },
    discountValue: { type: Number, default: 0, min: 0 },
    minOrderAmount: { type: Number, default: 0, min: 0 },
    maxDiscount: { type: Number, default: 0, min: 0 },
    freeDeliveryIncluded: { type: Boolean, default: false },
    applicableCategories: [{ type: String, trim: true }],
    applicableItemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'MenuItem' }],
    usageLimit: { type: Number, default: 0, min: 0 },
    perUserLimit: { type: Number, default: 0, min: 0 },
    firstOrderOnly: { type: Boolean, default: false },
    showOnStorefront: { type: Boolean, default: true },
    expiresAt: { type: Date, default: null },
    isActive: { type: Boolean, default: true },
    usedCount: { type: Number, default: 0, min: 0 },
  },
  { timestamps: true }
);

const expenseSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 120 },
    category: {
      type: String,
      enum: ['Gas/Fuel', 'Ingredients', 'Packaging', 'Delivery/Petrol', 'Staff', 'Other'],
      default: 'Other',
    },
    amount: { type: Number, required: true, min: 0 },
    note: { type: String, default: '', trim: true, maxlength: 200 },
    expenseDate: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const riderSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    phone: { type: String, required: true, unique: true, match: /^[6-9]\d{9}$/ },
    vehicleNote: { type: String, default: 'Bike', trim: true, maxlength: 60 },
    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

menuItemSchema.index({ sortOrder: 1, createdAt: 1 });
orderSchema.index({ phone: 1, createdAt: -1 });
orderSchema.index({ status: 1, createdAt: -1 });
orderSchema.index({ couponCode: 1, phone: 1 });
orderSchema.index({ createdAt: -1 });
couponSchema.index({ isActive: 1, showOnStorefront: 1 });
expenseSchema.index({ expenseDate: -1, createdAt: -1 });

const MenuItem = mongoose.model('MenuItem', menuItemSchema);
const Order = mongoose.model('Order', orderSchema);
const StoreSettings = mongoose.model('StoreSettings', storeSettingsSchema);
const BlockedNumber = mongoose.model('BlockedNumber', blockedNumberSchema);
const Coupon = mongoose.model('Coupon', couponSchema);
const Expense = mongoose.model('Expense', expenseSchema);
const Rider = mongoose.model('Rider', riderSchema);

// ----------------------------------------------------------------------------
// 3. INITIAL DATABASE SEEDING & HELPERS
// ----------------------------------------------------------------------------

const DEFAULT_CATEGORY_SORT_ORDER = {
  Snacks: 10,
  'Fast Food': 20,
  Chinese: 30,
  Meals: 40,
  Combos: 50,
  'Cold Drinks': 60,
  Beverages: 70,
};

const DEFAULT_MENU_ITEMS = [
  {
    nameHi: 'गरमा-गरम समोसा',
    nameEn: 'Samosa',
    descHi: 'तीखी हरी और मीठी इमली चटनी के साथ (1 पीस)',
    descEn: 'Crispy potato-stuffed pastry with green & tamarind chutney (1 pc)',
    category: 'Snacks',
    sellingPrice: 22,
    makingCost: 15,
    imageUrl: 'https://images.unsplash.com/photo-1601050690597-df0568f70950?auto=format&fit=crop&w=600&q=80',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: true,
    sortOrder: 1,
  },
  {
    nameHi: 'पैटीज़',
    nameEn: 'Patties',
    descHi: 'खस्ता बेक्ड पफ पेस्ट्री चटपटे मसाले के साथ (1 पीस)',
    descEn: 'Flaky golden puff pastry filled with spiced masala (1 pc)',
    category: 'Snacks',
    sellingPrice: 32,
    makingCost: 25,
    imageUrl: 'https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcT5tmlghErwH3kgJN2TChV6qrAt0ox0JnRpmfvO9lxPrfVl9KkSo1p14SM&s=10',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: false,
    sortOrder: 2,
  },
  {
    nameHi: 'ब्रेड पकौड़ा',
    nameEn: 'Bread Pakora',
    descHi: 'मसाला आलू स्टफिंग वाला कुरकुरा ब्रेड पकौड़ा',
    descEn: 'Golden gram-flour battered bread stuffed with spiced potato',
    category: 'Snacks',
    sellingPrice: 30,
    makingCost: 25,
    imageUrl: 'https://www.vegandietfood.com/wp-content/uploads/2021/10/Bread-Pakora-Recipe.jpg',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: false,
    sortOrder: 3,
  },
  {
    nameHi: 'वेज बर्गर',
    nameEn: 'Veg Burger',
    descHi: 'क्रिस्पी आलू टिक्की, प्याज़, टमाटर और स्पेशल सॉस',
    descEn: 'Crispy aloo tikki patty, fresh veggies & tangy house sauce',
    category: 'Fast Food',
    sellingPrice: 32,
    makingCost: 25,
    imageUrl: 'https://images.unsplash.com/photo-1568901346375-23c9450c58cd?auto=format&fit=crop&w=600&q=80',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: true,
    sortOrder: 4,
  },
  {
    nameHi: 'वेज चाउमीन (मीडियम प्लेट)',
    nameEn: 'Veg Chowmein (Medium)',
    descHi: 'ताज़ी सब्ज़ियों और देसी मसालों के साथ मीडियम प्लेट',
    descEn: 'Street-style stir-fried noodles tossed with crunchy veggies (Medium)',
    category: 'Chinese',
    sellingPrice: 35,
    makingCost: 30,
    imageUrl: 'https://images.unsplash.com/photo-1585032226651-759b368d7246?auto=format&fit=crop&w=600&q=80',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: true,
    sortOrder: 6,
  },
  {
    nameHi: 'एग चाउमीन (लार्ज)',
    nameEn: 'Egg Chowmein (Large)',
    descHi: 'डबल अंडे और स्पाइसी सॉस के साथ गरम फुल लार्ज चाउमीन',
    descEn: 'Large wok-tossed noodles with double scrambled egg & chili sauce',
    category: 'Chinese',
    sellingPrice: 60,
    makingCost: 50,
    imageUrl: 'https://images.unsplash.com/photo-1617093727343-374698b1b08d?auto=format&fit=crop&w=600&q=80',
    inStock: true,
    stockCount: null,
    isVeg: false,
    isPopular: false,
    sortOrder: 8,
  },
  {
    nameHi: 'वेज मोमोज़ (10 पीस)',
    nameEn: 'Veg Momos (10 Pcs)',
    descHi: 'तीखी लाल मोमो चटनी के साथ गरम स्टीम्ड मोमोज़',
    descEn: 'Steamed dumplings (10 pcs) served with fiery red garlic chutney',
    category: 'Chinese',
    sellingPrice: 57,
    makingCost: 40,
    imageUrl: 'https://someindiangirl.com/wp-content/uploads/2021/08/Paneer-Momo-Vegetable-Paneer-Momo-17-of-19-scaled.jpg',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: true,
    sortOrder: 10,
  },
  {
    nameHi: 'कचौड़ी सब्ज़ी (2 पीस)',
    nameEn: 'Kachori Sabzi',
    descHi: '2 खस्ता कचौड़ी और चटपटी आलू रसेदार सब्ज़ी',
    descEn: '2 crispy dal kachoris paired with spicy homestyle aloo sabzi',
    category: 'Meals',
    sellingPrice: 22,
    makingCost: 15,
    imageUrl: 'https://media.istockphoto.com/id/2235590451/photo/traditional-indian-kachori-with-aloo-sabzi-and-chole.jpg?s=612x612&w=0&k=20&c=Yc4eJZiX_Ye7A35TzgDi8LgCerOT2kSSnkg2pS1CSJM=',
    inStock: true,
    stockCount: null,
    isVeg: true,
    isPopular: false,
    sortOrder: 11,
  },
];

async function seedDatabaseIfEmpty() {
  const existingSettings = await StoreSettings.findOne({ key: 'default' });
  if (!existingSettings) {
    await StoreSettings.create({ key: 'default' });
    console.log('✅ Seeded default StoreSettings.');
  }

  const menuCount = await MenuItem.countDocuments();
  if (menuCount === 0) {
    await MenuItem.insertMany(DEFAULT_MENU_ITEMS);
    console.log(`✅ Seeded ${DEFAULT_MENU_ITEMS.length} default village menu items.`);
  }
}

async function getStoreSettings() {
  let settings = await StoreSettings.findOne({ key: 'default' });
  if (!settings) {
    settings = await StoreSettings.create({ key: 'default' });
  }
  return settings;
}

async function evaluateCouponAndTotals(subtotal, settings, rawCouponCode, rawPhone = '', cartLines = null) {
  let deliveryCharge =
    settings.freeDeliveryAbove > 0 && subtotal >= settings.freeDeliveryAbove
      ? 0
      : settings.deliveryCharge;
  let discountAmount = 0;
  let appliedCoupon = null;

  const cleanCode = typeof rawCouponCode === 'string' ? rawCouponCode.trim().toUpperCase() : '';
  if (cleanCode) {
    const coupon = await Coupon.findOne({ code: cleanCode, isActive: true }).lean();
    if (!coupon) {
      return { errorCode: 'INVALID_COUPON', error: 'Invalid or inactive coupon code.' };
    }
    if (coupon.expiresAt && new Date() > new Date(coupon.expiresAt)) {
      return { errorCode: 'COUPON_EXPIRED', error: `Coupon ${coupon.code} has expired.` };
    }
    if (coupon.usageLimit > 0 && (coupon.usedCount || 0) >= coupon.usageLimit) {
      return { errorCode: 'COUPON_LIMIT_REACHED', error: `Coupon ${coupon.code} usage limit (${coupon.usageLimit}) is full and can no longer be applied.` };
    }
    if (subtotal < (coupon.minOrderAmount || 0)) {
      return {
        errorCode: 'COUPON_MIN_ORDER',
        error: `Minimum order of ₹${coupon.minOrderAmount} required for coupon ${coupon.code}.`,
        minOrderAmount: coupon.minOrderAmount,
      };
    }

    const cleanPhone = normalizeIndianPhone(rawPhone || '');
    if (cleanPhone) {
      if (coupon.firstOrderOnly) {
        const priorOrders = await Order.countDocuments({
          phone: cleanPhone,
          status: { $ne: 'Cancelled' },
        });
        if (priorOrders > 0) {
          return {
            errorCode: 'COUPON_FIRST_ORDER_ONLY',
            error: `Coupon ${coupon.code} is valid only on your first order.`,
          };
        }
      }
      if (coupon.perUserLimit > 0) {
        const userUsed = await Order.countDocuments({
          phone: cleanPhone,
          couponCode: coupon.code,
          status: { $ne: 'Cancelled' },
        });
        if (userUsed >= coupon.perUserLimit) {
          return {
            errorCode: 'COUPON_USER_LIMIT',
            error: `You have already used coupon ${coupon.code} (${coupon.perUserLimit}x limit per mobile).`,
          };
        }
      }
    }

    const cats = Array.isArray(coupon.applicableCategories) ? coupon.applicableCategories.filter(Boolean) : [];
    const itemIds = Array.isArray(coupon.applicableItemIds) ? coupon.applicableItemIds.map((x) => String(x)) : [];
    let eligibleSubtotal = subtotal;

    if ((cats.length > 0 || itemIds.length > 0) && Array.isArray(cartLines) && cartLines.length > 0) {
      eligibleSubtotal = 0;
      for (const line of cartLines) {
        const matchCat = cats.length > 0 && cats.includes(line.category);
        const matchItem = itemIds.length > 0 && itemIds.includes(String(line.menuItemId));
        if (matchCat || matchItem) {
          eligibleSubtotal += (line.sellingPrice || 0) * (line.quantity || 0);
        }
      }
      if (eligibleSubtotal <= 0) {
        const targetNames = cats.length > 0 ? cats.join(', ') : 'selected items';
        return {
          errorCode: 'COUPON_ITEM_NOT_ELIGIBLE',
          error: `Coupon ${coupon.code} is valid only on: ${targetNames}.`,
        };
      }
    }

    const effectiveTarget =
      coupon.applyTarget || (coupon.discountType === 'FREE_DELIVERY' ? 'FREE_DELIVERY' : coupon.freeDeliveryIncluded ? 'BOTH' : 'ITEMS');

    if (effectiveTarget === 'FREE_DELIVERY' || coupon.discountType === 'FREE_DELIVERY') {
      deliveryCharge = 0;
    } else {
      if (coupon.discountType === 'FLAT') {
        discountAmount = Math.min(eligibleSubtotal, Math.round(coupon.discountValue));
      } else if (coupon.discountType === 'PERCENT') {
        let calc = Math.round((eligibleSubtotal * coupon.discountValue) / 100);
        if (coupon.maxDiscount > 0) calc = Math.min(calc, coupon.maxDiscount);
        discountAmount = Math.min(eligibleSubtotal, calc);
      }
      if (effectiveTarget === 'BOTH' || coupon.freeDeliveryIncluded) {
        deliveryCharge = 0;
      }
    }
    appliedCoupon = coupon;
  }

  const totalAmount = Math.max(0, subtotal - discountAmount) + deliveryCharge;
  return {
    deliveryCharge,
    discountAmount,
    couponCode: appliedCoupon ? appliedCoupon.code : '',
    appliedCoupon,
    totalAmount,
  };
}

// Consolidate duplicate menuItemId entries, validate items/stock without mutating DB yet
async function prepareOrderItems(rawItems, enforceStock = true) {
  if (!Array.isArray(rawItems) || rawItems.length === 0) {
    return { errorCode: 'EMPTY_CART', error: 'Your cart is empty.' };
  }

  const consolidated = new Map();
  for (const row of rawItems) {
    const idStr = String(row.menuItemId || '');
    const qty = parseInt(row.quantity, 10);
    if (!mongoose.Types.ObjectId.isValid(idStr) || !Number.isInteger(qty) || qty < 1 || qty > 100) {
      return { errorCode: 'INVALID_ITEM', error: 'One or more items in your cart are invalid.' };
    }
    consolidated.set(idStr, (consolidated.get(idStr) || 0) + qty);
  }

  const dbItems = await MenuItem.find({ _id: { $in: [...consolidated.keys()] } }).lean();
  const dbItemMap = new Map(dbItems.map((doc) => [String(doc._id), doc]));

  const orderItems = [];
  let subtotal = 0;
  let totalMakingCost = 0;
  const stockDecrements = [];

  for (const [idStr, qty] of consolidated.entries()) {
    const dbItem = dbItemMap.get(idStr);
    if (!dbItem) {
      return { errorCode: 'INVALID_ITEM', error: 'One or more items in your cart no longer exist.' };
    }
    if (enforceStock && !dbItem.inStock) {
      return {
        errorCode: 'OUT_OF_STOCK',
        error: `${dbItem.nameEn} is currently out of stock.`,
        itemNameEn: dbItem.nameEn,
        itemNameHi: dbItem.nameHi,
      };
    }
    if (enforceStock && dbItem.stockCount !== null && dbItem.stockCount !== undefined && qty > dbItem.stockCount) {
      return {
        errorCode: 'INSUFFICIENT_STOCK',
        error: `Only ${dbItem.stockCount} left for ${dbItem.nameEn}.`,
        itemNameEn: dbItem.nameEn,
        itemNameHi: dbItem.nameHi,
        available: dbItem.stockCount,
      };
    }

    subtotal += dbItem.sellingPrice * qty;
    totalMakingCost += dbItem.makingCost * qty;
    orderItems.push({
      menuItemId: dbItem._id,
      nameHi: dbItem.nameHi,
      nameEn: dbItem.nameEn,
      category: dbItem.category || 'Snacks',
      quantity: qty,
      sellingPrice: dbItem.sellingPrice,
      makingCost: dbItem.makingCost,
    });

    if (dbItem.stockCount !== null && dbItem.stockCount !== undefined) {
      const decQty = enforceStock ? qty : Math.min(dbItem.stockCount, qty);
      if (decQty > 0) stockDecrements.push({ id: dbItem._id, qty: decQty });
    }
  }

  return { orderItems, subtotal, totalMakingCost, stockDecrements };
}

// Atomically decrement limited-stock items after ALL order validations pass (with rollback on race condition)
async function commitStockDecrements(stockDecrements, enforceStock = true) {
  const applied = [];
  for (const dec of stockDecrements) {
    const updatedItem = await MenuItem.findOneAndUpdate(
      { _id: dec.id, stockCount: { $gte: dec.qty } },
      { $inc: { stockCount: -dec.qty } },
      { returnDocument: 'after' }
    );
    if (!updatedItem) {
      if (enforceStock) {
        // Rollback previous decrements in this order
        for (const prev of applied) {
          await MenuItem.updateOne({ _id: prev.id }, { $inc: { stockCount: prev.qty }, $set: { inStock: true } });
        }
        return { errorCode: 'OUT_OF_STOCK', error: 'Item just went out of stock. Please refresh.' };
      }
      continue;
    }
    applied.push(dec);
    if (updatedItem.stockCount !== null && updatedItem.stockCount <= 0 && updatedItem.inStock) {
      await MenuItem.updateOne({ _id: updatedItem._id }, { $set: { inStock: false, stockCount: 0 } });
    }
  }
  return { ok: true };
}

// ----------------------------------------------------------------------------
// 4. PUBLIC CUSTOMER API ROUTES
// ----------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.json({
    ok: true,
    app: 'Gaon Rasoi Backend API',
    health: '/api/health',
  });
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    status: 'running',
    dbConnected: mongoose.connection.readyState === 1,
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/store', async (req, res) => {
  try {
    const now = new Date();
    const [settings, menu, rawCoupons] = await Promise.all([
      getStoreSettings(),
      MenuItem.find({}).select('-makingCost -__v').sort({ sortOrder: 1, createdAt: 1 }).lean(),
      Coupon.find({
        isActive: true,
        showOnStorefront: true,
        $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
      })
        .select('code titleHi titleEn applyTarget discountType discountValue minOrderAmount maxDiscount freeDeliveryIncluded applicableCategories applicableItemIds firstOrderOnly perUserLimit usageLimit usedCount expiresAt')
        .sort({ minOrderAmount: 1, createdAt: -1 })
        .lean(),
    ]);

    const coupons = rawCoupons.filter((c) => !c.usageLimit || (c.usedCount || 0) < c.usageLimit);

    res.json({
      serverNow: now.toISOString(),
      settings: {
        shopNameHi: settings.shopNameHi,
        shopNameEn: settings.shopNameEn,
        isOpen: settings.isOpen,
        deliveryCharge: settings.deliveryCharge,
        freeDeliveryAbove: settings.freeDeliveryAbove || 0,
        minOrderAmount: settings.minOrderAmount,
        deliveryRadiusKm: settings.deliveryRadiusKm,
        openHoursHi: settings.openHoursHi || '',
        openHoursEn: settings.openHoursEn || '',
        supportPhone: settings.supportPhone || '',
        upiId: settings.upiId || '',
        announcementHi: settings.announcementHi || '',
        announcementEn: settings.announcementEn || '',
        timerTitleHi: settings.timerTitleHi || '',
        timerTitleEn: settings.timerTitleEn || '',
        timerEndsAt: settings.timerEndsAt || null,
      },
      menu,
      coupons,
    });
  } catch (err) {
    console.error('GET /api/store error:', err);
    res.status(500).json({ error: 'Failed to load store data.' });
  }
});

app.post('/api/coupons/validate', couponValidateLimiter, async (req, res) => {
  try {
    const { code, subtotal, phone, items } = req.body || {};
    let numSub = Number(subtotal) || 0;
    let cartLines = null;
    if (Array.isArray(items) && items.length > 0) {
      const itemRes = await prepareOrderItems(items, false);
      if (!itemRes.error) {
        numSub = itemRes.subtotal;
        cartLines = itemRes.orderItems;
      }
    }
    const settings = await getStoreSettings();
    const result = await evaluateCouponAndTotals(numSub, settings, code, phone || '', cartLines);
    if (result.error) {
      return res.status(400).json({ code: result.errorCode, error: result.error, minOrderAmount: result.minOrderAmount });
    }
    res.json({
      valid: true,
      code: result.couponCode,
      titleHi: result.appliedCoupon.titleHi || '',
      titleEn: result.appliedCoupon.titleEn || '',
      applyTarget: result.appliedCoupon.applyTarget || (result.appliedCoupon.discountType === 'FREE_DELIVERY' ? 'FREE_DELIVERY' : 'ITEMS'),
      discountAmount: result.discountAmount,
      discountValue: result.appliedCoupon.discountValue,
      maxDiscount: result.appliedCoupon.maxDiscount || 0,
      minOrderAmount: result.appliedCoupon.minOrderAmount || 0,
      freeDeliveryIncluded: Boolean(result.appliedCoupon.freeDeliveryIncluded || result.appliedCoupon.discountType === 'FREE_DELIVERY' || result.appliedCoupon.applyTarget === 'BOTH'),
      applicableCategories: result.appliedCoupon.applicableCategories || [],
      applicableItemIds: result.appliedCoupon.applicableItemIds || [],
      firstOrderOnly: Boolean(result.appliedCoupon.firstOrderOnly),
      perUserLimit: result.appliedCoupon.perUserLimit || 0,
      usageLimit: result.appliedCoupon.usageLimit || 0,
      usedCount: result.appliedCoupon.usedCount || 0,
      deliveryCharge: result.deliveryCharge,
      totalAmount: result.totalAmount,
      discountType: result.appliedCoupon.discountType,
    });
  } catch (err) {
    console.error('POST /api/coupons/validate error:', err);
    res.status(500).json({ error: 'Failed to validate coupon.' });
  }
});

app.post('/api/orders', orderCreateLimiter, async (req, res) => {
  let claimedCouponId = null;
  let committedStockDecrements = [];
  try {
    const { customerName, phone, address, customerNote, gpsLocation, items, couponCode } = req.body || {};

    const settings = await getStoreSettings();
    if (!settings.isOpen) {
      return res.status(400).json({
        code: 'SHOP_CLOSED',
        error: 'Shop is currently closed. Please order during open hours.',
      });
    }

    const cleanName = typeof customerName === 'string' ? customerName.trim() : '';
    const cleanPhone = normalizeIndianPhone(phone);
    const cleanAddress = typeof address === 'string' ? address.trim() : '';
    const cleanNote = typeof customerNote === 'string' ? customerNote.trim().slice(0, 200) : '';

    if (cleanName.length < 2) {
      return res.status(400).json({ code: 'INVALID_NAME', error: 'Please enter a valid customer name.' });
    }
    if (!cleanPhone) {
      return res.status(400).json({ code: 'INVALID_PHONE', error: 'Please enter a valid 10-digit Indian mobile number.' });
    }
    if (cleanAddress.length < 4) {
      return res.status(400).json({ code: 'INVALID_ADDRESS', error: 'Please enter your Mohalla / Gali / Landmark address.' });
    }

    const isBlocked = await BlockedNumber.findOne({ phone: cleanPhone }).lean();
    if (isBlocked) {
      return res.status(403).json({
        code: 'PHONE_BLOCKED',
        error: 'This phone number has been blocked from placing orders.',
      });
    }

    const itemResult = await prepareOrderItems(items, true);
    if (itemResult.error) {
      return res.status(400).json({
        code: itemResult.errorCode,
        error: itemResult.error,
        itemNameEn: itemResult.itemNameEn,
        itemNameHi: itemResult.itemNameHi,
      });
    }

    const { orderItems, subtotal, totalMakingCost, stockDecrements } = itemResult;

    if (subtotal < settings.minOrderAmount) {
      return res.status(400).json({
        code: 'BELOW_MIN_ORDER',
        error: `Minimum order amount is ₹${settings.minOrderAmount}.`,
        minOrderAmount: settings.minOrderAmount,
      });
    }

    const pricing = await evaluateCouponAndTotals(subtotal, settings, couponCode, cleanPhone, orderItems);
    if (pricing.error) {
      return res.status(400).json({ code: pricing.errorCode, error: pricing.error });
    }

    if (pricing.appliedCoupon) {
      const claimedCoupon = await Coupon.findOneAndUpdate(
        {
          _id: pricing.appliedCoupon._id,
          isActive: true,
          $or: [{ usageLimit: 0 }, { $expr: { $lt: ['$usedCount', '$usageLimit'] } }],
        },
        { $inc: { usedCount: 1 } },
        { returnDocument: 'after' }
      ).lean();
      if (!claimedCoupon) {
        return res.status(400).json({
          code: 'COUPON_LIMIT_REACHED',
          error: `Coupon ${pricing.couponCode} usage limit has just been reached.`,
        });
      }
      claimedCouponId = pricing.appliedCoupon._id;
    }

    const stockCommit = await commitStockDecrements(stockDecrements, true);
    if (stockCommit.error) {
      if (claimedCouponId) {
        await Coupon.updateOne(
          { _id: claimedCouponId, usedCount: { $gt: 0 } },
          { $inc: { usedCount: -1 } }
        );
        claimedCouponId = null;
      }
      return res.status(400).json({ code: stockCommit.errorCode, error: stockCommit.error });
    }
    committedStockDecrements = stockDecrements;

    let cleanGps = { lat: null, lng: null, mapLink: '' };
    if (
      gpsLocation &&
      typeof gpsLocation.lat === 'number' &&
      typeof gpsLocation.lng === 'number' &&
      Number.isFinite(gpsLocation.lat) &&
      Number.isFinite(gpsLocation.lng) &&
      Math.abs(gpsLocation.lat) <= 90 &&
      Math.abs(gpsLocation.lng) <= 180
    ) {
      const lat = Number(gpsLocation.lat.toFixed(6));
      const lng = Number(gpsLocation.lng.toFixed(6));
      cleanGps = { lat, lng, mapLink: `https://maps.google.com/?q=${lat},${lng}` };
    }

    const randomSuffix = crypto.randomInt(100000, 999999);
    const orderNumber = `GR-${Date.now().toString().slice(-4)}${randomSuffix}`;
    const createdNow = new Date();
    const cancelDeadlineAt = new Date(createdNow.getTime() + 5 * 60 * 1000);

    const newOrder = await Order.create({
      orderNumber,
      customerName: cleanName,
      phone: cleanPhone,
      address: cleanAddress,
      customerNote: cleanNote,
      gpsLocation: cleanGps,
      items: orderItems,
      subtotal,
      discountAmount: pricing.discountAmount,
      couponCode: pricing.couponCode,
      deliveryCharge: pricing.deliveryCharge,
      totalAmount: pricing.totalAmount,
      totalMakingCost,
      paymentMethod: 'COD',
      source: 'Website',
      status: 'Pending',
      cancelDeadlineAt,
    });
    claimedCouponId = null;
    committedStockDecrements = [];

    res.status(201).json({
      message: 'Order placed successfully!',
      serverNow: createdNow.toISOString(),
      order: {
        orderNumber: newOrder.orderNumber,
        customerName: newOrder.customerName,
        phone: newOrder.phone,
        address: newOrder.address,
        status: newOrder.status,
        subtotal: newOrder.subtotal,
        discountAmount: newOrder.discountAmount,
        couponCode: newOrder.couponCode,
        deliveryCharge: newOrder.deliveryCharge,
        totalAmount: newOrder.totalAmount,
        paymentMethod: newOrder.paymentMethod,
        items: newOrder.items.map((it) => ({
          nameHi: it.nameHi,
          nameEn: it.nameEn,
          quantity: it.quantity,
          sellingPrice: it.sellingPrice,
        })),
        cancelDeadlineAt: newOrder.cancelDeadlineAt,
        createdAt: newOrder.createdAt,
      },
    });
  } catch (err) {
    if (claimedCouponId) {
      await Coupon.updateOne(
        { _id: claimedCouponId, usedCount: { $gt: 0 } },
        { $inc: { usedCount: -1 } }
      ).catch(() => {});
    }
    for (const dec of committedStockDecrements) {
      await MenuItem.updateOne(
        { _id: dec.id, stockCount: { $ne: null } },
        { $inc: { stockCount: dec.qty }, $set: { inStock: true } }
      ).catch(() => {});
    }
    console.error('POST /api/orders error:', err);
    res.status(500).json({ error: 'Could not place order. Please try again.' });
  }
});

const ORDER_STATUS_RANK = {
  Pending: 0,
  Cooking: 1,
  'Out for Delivery': 2,
  Delivered: 3,
  Cancelled: 99,
};

async function applyScheduledOrderTransition(orderDoc, now = new Date()) {
  if (!orderDoc || orderDoc.status === 'Delivered' || orderDoc.status === 'Cancelled') {
    return orderDoc;
  }
  const sch = orderDoc.statusSchedule;
  if (!sch) return orderDoc;

  const curRank = ORDER_STATUS_RANK[orderDoc.status] ?? 0;
  let nextStatus = orderDoc.status;

  if (sch.deliveredAt && now >= new Date(sch.deliveredAt)) {
    nextStatus = 'Delivered';
  } else if (sch.outForDeliveryAt && now >= new Date(sch.outForDeliveryAt) && curRank < 2) {
    nextStatus = 'Out for Delivery';
  } else if (sch.cookingAt && now >= new Date(sch.cookingAt) && curRank < 1) {
    nextStatus = 'Cooking';
  }

  if (nextStatus !== orderDoc.status) {
    const updateSet = { status: nextStatus };
    if (nextStatus === 'Delivered' && (!orderDoc.paymentCollectedMode || orderDoc.paymentCollectedMode === 'Pending')) {
      updateSet.paymentCollectedMode = 'Cash';
    }
    await Order.updateOne({ _id: orderDoc._id, status: orderDoc.status }, { $set: updateSet });
    orderDoc.status = nextStatus;
    if (updateSet.paymentCollectedMode) orderDoc.paymentCollectedMode = updateSet.paymentCollectedMode;
  }
  return orderDoc;
}

app.get('/api/orders/history', orderLookupLimiter, async (req, res) => {
  try {
    const cleanPhone = normalizeIndianPhone(req.query.phone || '');
    if (!cleanPhone) {
      return res.status(400).json({ code: 'INVALID_PHONE', error: 'Valid 10-digit phone number is required.' });
    }
    const orders = await Order.find({
      phone: cleanPhone,
      hiddenByCustomer: { $ne: true },
    })
      .select(
        'orderNumber customerName phone address status subtotal discountAmount couponCode deliveryCharge totalAmount assignedRider statusSchedule cancelDeadlineAt cancelledBy cancelledAt items createdAt updatedAt'
      )
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    const now = new Date();
    for (const ord of orders) {
      if (['Pending', 'Cooking', 'Out for Delivery'].includes(ord.status)) {
        await applyScheduledOrderTransition(ord, now);
      }
      if (!ord.cancelDeadlineAt && ord.createdAt) {
        ord.cancelDeadlineAt = new Date(new Date(ord.createdAt).getTime() + 5 * 60 * 1000);
      }
    }

    res.json({ orders, serverNow: now.toISOString() });
  } catch (err) {
    console.error('GET /api/orders/history error:', err);
    res.status(500).json({ error: 'Failed to load order history.' });
  }
});

async function handleHideCustomerOrder(req, res) {
  try {
    const cleanPhone = normalizeIndianPhone((req.body && req.body.phone) || req.query.phone || '');
    if (!cleanPhone) {
      return res.status(400).json({ code: 'INVALID_PHONE', error: 'Valid 10-digit phone number is required.' });
    }
    const cleanOrderNum = String(req.params.orderNumber || '').trim().toUpperCase();
    const order = await Order.findOne({ orderNumber: cleanOrderNum, phone: cleanPhone }).lean();
    if (!order) {
      return res.status(404).json({ code: 'ORDER_NOT_FOUND', error: 'Order not found.' });
    }

    const now = new Date();
    await applyScheduledOrderTransition(order, now);

    if (!['Delivered', 'Cancelled'].includes(order.status)) {
      return res.status(400).json({
        code: 'CANNOT_DELETE_ACTIVE_ORDER',
        error: 'Only delivered or cancelled orders can be deleted from your history.',
        serverNow: now.toISOString(),
      });
    }

    await Order.updateOne(
      { _id: order._id },
      { $set: { hiddenByCustomer: true, customerHiddenAt: now } }
    );

    res.json({
      message: 'Order deleted from your history.',
      orderNumber: cleanOrderNum,
      serverNow: now.toISOString(),
    });
  } catch (err) {
    console.error('Hide customer order error:', err);
    res.status(500).json({ error: 'Failed to delete order from history.' });
  }
}

app.delete('/api/orders/:orderNumber/history', handleHideCustomerOrder);
app.post('/api/orders/:orderNumber/hide', handleHideCustomerOrder);

app.get('/api/orders/track/:orderNumber', orderLookupLimiter, async (req, res) => {
  try {
    const cleanPhone = normalizeIndianPhone(req.query.phone || '');
    if (!cleanPhone) {
      return res.status(400).json({ error: 'Valid 10-digit phone number is required.' });
    }
    const cleanOrderNum = String(req.params.orderNumber || '').trim().toUpperCase();
    const order = await Order.findOne({
      orderNumber: cleanOrderNum,
      phone: cleanPhone,
    })
      .select(
        'orderNumber customerName address status totalAmount discountAmount couponCode assignedRider statusSchedule cancelDeadlineAt cancelledBy cancelledAt items createdAt updatedAt'
      )
      .lean();

    if (!order) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    const now = new Date();
    await applyScheduledOrderTransition(order, now);
    if (!order.cancelDeadlineAt && order.createdAt) {
      order.cancelDeadlineAt = new Date(new Date(order.createdAt).getTime() + 5 * 60 * 1000);
    }

    res.json({ order, serverNow: now.toISOString() });
  } catch (err) {
    console.error('GET /api/orders/track error:', err);
    res.status(500).json({ error: 'Failed to check order status.' });
  }
});

app.post('/api/orders/:orderNumber/cancel', orderCancelLimiter, async (req, res) => {
  try {
    const cleanPhone = normalizeIndianPhone((req.body && req.body.phone) || req.query.phone || '');
    if (!cleanPhone) {
      return res.status(400).json({ code: 'INVALID_PHONE', error: 'Valid 10-digit phone number is required.' });
    }
    const cleanOrderNum = String(req.params.orderNumber || '').trim().toUpperCase();
    const order = await Order.findOne({ orderNumber: cleanOrderNum, phone: cleanPhone }).lean();
    if (!order) {
      return res.status(404).json({ code: 'ORDER_NOT_FOUND', error: 'Order not found.' });
    }

    const now = new Date();
    await applyScheduledOrderTransition(order, now);

    if (order.status === 'Cancelled') {
      return res.json({
        message: 'Order is already cancelled.',
        order,
        serverNow: now.toISOString(),
      });
    }
    if (order.status === 'Delivered' || order.status === 'Out for Delivery') {
      return res.status(403).json({
        code: 'CANCEL_NOT_ALLOWED_STATUS',
        error: 'Order is already out for delivery or delivered and cannot be cancelled.',
        serverNow: now.toISOString(),
      });
    }

    const deadline = order.cancelDeadlineAt
      ? new Date(order.cancelDeadlineAt)
      : new Date(new Date(order.createdAt).getTime() + 5 * 60 * 1000);

    if (now.getTime() > deadline.getTime()) {
      return res.status(403).json({
        code: 'CANCEL_WINDOW_EXPIRED',
        error: '5-minute cancellation window has expired. Your order is locked and must be accepted.',
        serverNow: now.toISOString(),
        cancelDeadlineAt: deadline.toISOString(),
      });
    }

    const updated = await Order.findOneAndUpdate(
      {
        _id: order._id,
        status: { $in: ['Pending', 'Cooking'] },
        $or: [{ cancelDeadlineAt: { $gte: now } }, { cancelDeadlineAt: null }],
      },
      {
        $set: {
          status: 'Cancelled',
          cancelledBy: 'Customer',
          cancelledAt: now,
          paymentCollectedMode: 'Pending',
          adminNote: order.adminNote
            ? `${order.adminNote} | Customer cancelled within 5m`
            : 'Customer cancelled within 5m window',
          statusSchedule: {
            cookingAt: null,
            outForDeliveryAt: null,
            deliveredAt: null,
            etaEndsAt: null,
            noteHi: '',
            noteEn: '',
            updatedAt: null,
          },
        },
      },
      { returnDocument: 'after' }
    ).lean();

    if (!updated) {
      return res.status(409).json({
        code: 'CANCEL_CONFLICT',
        error: 'Order could not be cancelled (already locked or updated).',
        serverNow: now.toISOString(),
      });
    }

    // Safely restore limited-stock items only (keep unlimited stockCount === null untouched)
    for (const it of order.items || []) {
      if (it.menuItemId && it.quantity > 0) {
        await MenuItem.updateOne(
          { _id: it.menuItemId, stockCount: { $ne: null } },
          { $inc: { stockCount: it.quantity }, $set: { inStock: true } }
        );
      }
    }

    // Restore coupon usage count if a coupon was applied
    if (order.couponCode) {
      await Coupon.updateOne({ code: order.couponCode, usedCount: { $gt: 0 } }, { $inc: { usedCount: -1 } });
    }

    res.json({
      message: 'Order cancelled successfully within the 5-minute window.',
      serverNow: now.toISOString(),
      order: {
        orderNumber: updated.orderNumber,
        customerName: updated.customerName,
        address: updated.address,
        status: updated.status,
        cancelledBy: updated.cancelledBy,
        cancelledAt: updated.cancelledAt,
        cancelDeadlineAt: deadline,
      },
    });
  } catch (err) {
    console.error('POST /api/orders/:orderNumber/cancel error:', err);
    res.status(500).json({ error: 'Could not cancel order. Please try again.' });
  }
});

// ----------------------------------------------------------------------------
// 5. ADMIN AUTHENTICATION & PROTECTED DASHBOARD ROUTES
// ----------------------------------------------------------------------------

app.post('/api/admin/login', (req, res) => {
  const clientIp = req.ip || 'unknown';
  const rateCheck = checkLoginRateLimit(clientIp);
  if (!rateCheck.allowed) {
    return res.status(429).json({
      error: `Too many failed attempts. Try again in ${rateCheck.retryAfterSec} seconds.`,
    });
  }

  const configuredPassword = process.env.ADMIN_PASSWORD;
  if (!configuredPassword) {
    return res.status(503).json({
      error: 'ADMIN_PASSWORD environment variable is not set on Render.',
    });
  }

  const { password } = req.body || {};
  if (typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Password is required.' });
  }

  if (!safeCompareStrings(password, configuredPassword)) {
    recordFailedLogin(clientIp);
    return res.status(401).json({ error: 'Incorrect password.' });
  }

  clearFailedLogins(clientIp);
  const token = createAdminToken();
  res.json({ token, expiresInSeconds: 24 * 60 * 60 });
});

app.get('/api/admin/verify', requireAdmin, (req, res) => {
  res.json({ valid: true });
});

// --- LIVE ORDERS MANAGEMENT ---

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    const now = new Date();
    const activeScheduled = await Order.find({
      status: { $in: ['Pending', 'Cooking', 'Out for Delivery'] },
      'statusSchedule.updatedAt': { $ne: null },
    }).lean();
    for (const ord of activeScheduled) {
      await applyScheduledOrderTransition(ord, now);
    }

    const filter = {};
    if (req.query.status && req.query.status !== 'All') {
      filter.status = req.query.status;
    }
    const orders = await Order.find(filter).sort({ createdAt: -1 }).limit(300).lean();
    const blockedDocs = await BlockedNumber.find({}).select('phone').lean();
    const blockedSet = blockedDocs.map((b) => b.phone);
    res.json({ orders, blockedNumbers: blockedSet, serverNow: now.toISOString() });
  } catch (err) {
    console.error('GET /api/admin/orders error:', err);
    res.status(500).json({ error: 'Failed to load orders.' });
  }
});

app.post('/api/admin/orders', requireAdmin, async (req, res) => {
  try {
    const { customerName, phone, address, customerNote, items, deliveryChargeOverride, status, adminNote } =
      req.body || {};
    const cleanName = typeof customerName === 'string' ? customerName.trim() : '';
    const cleanPhone = normalizeIndianPhone(phone);
    const cleanAddress = typeof address === 'string' ? address.trim() : '';

    if (cleanName.length < 2 || !cleanPhone || cleanAddress.length < 2) {
      return res.status(400).json({ error: 'Valid customer name, 10-digit Indian phone, and address are required.' });
    }

    const itemResult = await prepareOrderItems(items, false);
    if (itemResult.error) {
      return res.status(400).json({ error: itemResult.error });
    }
    const { orderItems, subtotal, totalMakingCost, stockDecrements } = itemResult;

    const settings = await getStoreSettings();
    const parsedDel = Number(deliveryChargeOverride);
    const deliveryCharge =
      deliveryChargeOverride !== undefined && deliveryChargeOverride !== '' && Number.isFinite(parsedDel)
        ? Math.max(0, parsedDel)
        : settings.deliveryCharge;
    const totalAmount = subtotal + deliveryCharge;
    const allowedStatuses = ['Pending', 'Cooking', 'Out for Delivery', 'Delivered'];
    const initialStatus = allowedStatuses.includes(status) ? status : 'Cooking';
    await commitStockDecrements(stockDecrements, false);
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);

    const newOrder = await Order.create({
      orderNumber: `PH-${Date.now().toString().slice(-4)}${randomSuffix}`,
      customerName: cleanName,
      phone: cleanPhone,
      address: cleanAddress,
      customerNote: customerNote ? String(customerNote).trim().slice(0, 200) : '',
      items: orderItems,
      subtotal,
      discountAmount: 0,
      deliveryCharge,
      totalAmount,
      totalMakingCost,
      paymentMethod: 'COD',
      paymentCollectedMode: initialStatus === 'Delivered' ? 'Cash' : 'Pending',
      source: 'Phone',
      adminNote: adminNote ? String(adminNote).trim() : '',
      status: initialStatus,
    });

    res.status(201).json({ order: newOrder });
  } catch (err) {
    console.error('POST /api/admin/orders error:', err);
    res.status(500).json({ error: 'Failed to create manual phone order.' });
  }
});

app.patch('/api/admin/orders/:id/status', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const allowedStatuses = ['Pending', 'Cooking', 'Out for Delivery', 'Delivered', 'Cancelled'];
    const { status, adminNote, paymentCollectedMode, riderId } = req.body || {};

    const existingOrder = await Order.findById(req.params.id).lean();
    if (!existingOrder) {
      return res.status(404).json({ error: 'Order not found.' });
    }

    const updateDoc = {};
    if (status !== undefined) {
      if (!allowedStatuses.includes(status)) {
        return res.status(400).json({ error: 'Invalid order status.' });
      }
      updateDoc.status = status;
      if (status === 'Delivered' && !paymentCollectedMode && existingOrder.paymentCollectedMode === 'Pending') {
        updateDoc.paymentCollectedMode = 'Cash';
      } else if (status === 'Cancelled') {
        updateDoc.paymentCollectedMode = 'Pending';
        updateDoc.cancelledBy = 'Admin';
        updateDoc.cancelledAt = new Date();
      }
      if (status === 'Delivered' || status === 'Cancelled') {
        updateDoc.statusSchedule = {
          cookingAt: null,
          outForDeliveryAt: null,
          deliveredAt: null,
          etaEndsAt: null,
          noteHi: '',
          noteEn: '',
          updatedAt: null,
        };
      }
    }

    if (adminNote !== undefined) updateDoc.adminNote = String(adminNote).trim().slice(0, 250);
    if (paymentCollectedMode !== undefined) {
      if (!['Pending', 'Cash', 'UPI'].includes(paymentCollectedMode)) {
        return res.status(400).json({ error: 'Invalid payment collection mode.' });
      }
      updateDoc.paymentCollectedMode = paymentCollectedMode;
    }

    if (riderId !== undefined) {
      if (!riderId) {
        updateDoc.assignedRider = { riderId: null, name: '', phone: '' };
      } else {
        if (!mongoose.Types.ObjectId.isValid(riderId)) {
          return res.status(400).json({ error: 'Invalid rider ID.' });
        }
        const rider = await Rider.findById(riderId).lean();
        if (!rider) return res.status(404).json({ error: 'Rider not found.' });
        updateDoc.assignedRider = { riderId: rider._id, name: rider.name, phone: rider.phone };
      }
    }

    const queryFilter = status === 'Cancelled' ? { _id: req.params.id, status: { $ne: 'Cancelled' } } : { _id: req.params.id };
    let updated = await Order.findOneAndUpdate(queryFilter, updateDoc, { returnDocument: 'after' }).lean();
    if (!updated) {
      if (status === 'Cancelled' && existingOrder.status === 'Cancelled') {
        updated = await Order.findByIdAndUpdate(req.params.id, updateDoc, { returnDocument: 'after' }).lean();
      } else {
        return res.status(404).json({ error: 'Order not found.' });
      }
    }

    // If Admin cancelled an active order, restore limited-stock counts and free up coupon slot
    if (status === 'Cancelled' && existingOrder.status !== 'Cancelled') {
      for (const it of existingOrder.items || []) {
        if (it.menuItemId && it.quantity > 0) {
          await MenuItem.updateOne(
            { _id: it.menuItemId, stockCount: { $ne: null } },
            { $inc: { stockCount: it.quantity }, $set: { inStock: true } }
          );
        }
      }
      if (existingOrder.couponCode) {
        await Coupon.updateOne(
          { code: existingOrder.couponCode, usedCount: { $gt: 0 } },
          { $inc: { usedCount: -1 } }
        );
      }
    }

    res.json({ order: updated });
  } catch (err) {
    console.error('PATCH /api/admin/orders/:id/status error:', err);
    res.status(500).json({ error: 'Failed to update order.' });
  }
});

app.patch('/api/admin/orders/:id/schedule', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const existingOrder = await Order.findById(req.params.id).lean();
    if (!existingOrder) {
      return res.status(404).json({ error: 'Order not found.' });
    }
    if (existingOrder.status === 'Delivered' || existingOrder.status === 'Cancelled') {
      return res.status(400).json({ error: 'Cannot schedule a Delivered or Cancelled order.' });
    }

    const {
      cookingInMin,
      outForDeliveryInMin,
      deliveredInMin,
      etaInMin,
      noteHi,
      noteEn,
      clearSchedule,
    } = req.body || {};

    const nowMs = Date.now();
    if (clearSchedule === true) {
      const cleared = await Order.findByIdAndUpdate(
        req.params.id,
        {
          $set: {
            statusSchedule: {
              cookingAt: null,
              outForDeliveryAt: null,
              deliveredAt: null,
              etaEndsAt: null,
              noteHi: '',
              noteEn: '',
              updatedAt: null,
            },
          },
        },
        { returnDocument: 'after' }
      ).lean();
      return res.json({ order: cleared, serverNow: new Date(nowMs).toISOString() });
    }

    const parseMin = (val) => {
      if (val === undefined || val === null || val === '') return null;
      const n = Number(val);
      if (!Number.isFinite(n) || n < 0 || n > 1440) return null;
      return n;
    };

    const cMin = parseMin(cookingInMin);
    const oMin = parseMin(outForDeliveryInMin);
    const dMin = parseMin(deliveredInMin);
    const eMin = parseMin(etaInMin);

    let nextStatus = existingOrder.status;
    let nextPaymentMode = existingOrder.paymentCollectedMode;
    if (dMin === 0 && (ORDER_STATUS_RANK[nextStatus] ?? 0) < 3) {
      nextStatus = 'Delivered';
      if (!nextPaymentMode || nextPaymentMode === 'Pending') {
        nextPaymentMode = 'Cash';
      }
    } else if (oMin === 0 && (ORDER_STATUS_RANK[nextStatus] ?? 0) < 2) {
      nextStatus = 'Out for Delivery';
    } else if (cMin === 0 && (ORDER_STATUS_RANK[nextStatus] ?? 0) < 1) {
      nextStatus = 'Cooking';
    }

    const cookingAt = cMin !== null && cMin > 0 ? new Date(nowMs + cMin * 60000) : null;
    const outForDeliveryAt = oMin !== null && oMin > 0 ? new Date(nowMs + oMin * 60000) : null;
    const deliveredAt = dMin !== null && dMin > 0 ? new Date(nowMs + dMin * 60000) : null;

    let etaEndsAt = null;
    if (eMin !== null && eMin > 0) {
      etaEndsAt = new Date(nowMs + eMin * 60000);
    } else if (deliveredAt) {
      etaEndsAt = deliveredAt;
    } else if (outForDeliveryAt) {
      etaEndsAt = outForDeliveryAt;
    } else if (cookingAt) {
      etaEndsAt = cookingAt;
    }

    const scheduleObj =
      nextStatus === 'Delivered'
        ? {
            cookingAt: null,
            outForDeliveryAt: null,
            deliveredAt: null,
            etaEndsAt: null,
            noteHi: '',
            noteEn: '',
            updatedAt: null,
          }
        : {
            cookingAt,
            outForDeliveryAt,
            deliveredAt,
            etaEndsAt,
            noteHi: noteHi ? String(noteHi).trim().slice(0, 140) : '',
            noteEn: noteEn ? String(noteEn).trim().slice(0, 140) : '',
            updatedAt: new Date(nowMs),
          };

    const updated = await Order.findByIdAndUpdate(
      req.params.id,
      { $set: { status: nextStatus, paymentCollectedMode: nextPaymentMode, statusSchedule: scheduleObj } },
      { returnDocument: 'after' }
    ).lean();

    res.json({ order: updated, serverNow: new Date(nowMs).toISOString() });
  } catch (err) {
    console.error('PATCH /api/admin/orders/:id/schedule error:', err);
    res.status(500).json({ error: 'Failed to save order schedule.' });
  }
});

app.delete('/api/admin/orders/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const deleted = await Order.findByIdAndDelete(req.params.id).lean();
    if (!deleted) return res.status(404).json({ error: 'Order not found.' });
    if (deleted.status !== 'Cancelled' && deleted.status !== 'Delivered') {
      for (const it of deleted.items || []) {
        if (it.menuItemId && it.quantity > 0) {
          await MenuItem.updateOne(
            { _id: it.menuItemId, stockCount: { $ne: null } },
            { $inc: { stockCount: it.quantity }, $set: { inStock: true } }
          );
        }
      }
      if (deleted.couponCode) {
        await Coupon.updateOne(
          { code: deleted.couponCode, usedCount: { $gt: 0 } },
          { $inc: { usedCount: -1 } }
        );
      }
    }
    res.json({ deletedId: req.params.id });
  } catch (err) {
    console.error('DELETE /api/admin/orders/:id error:', err);
    res.status(500).json({ error: 'Failed to delete order.' });
  }
});

// --- DELIVERY RIDERS & COD CASH RECONCILIATION ---

app.get('/api/admin/riders', requireAdmin, async (req, res) => {
  try {
    const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
    const nowIst = new Date(Date.now() + IST_OFFSET_MS);
    const startOfTodayIstInUtc = new Date(
      Date.UTC(nowIst.getUTCFullYear(), nowIst.getUTCMonth(), nowIst.getUTCDate()) - IST_OFFSET_MS
    );

    const [riders, riderOrders] = await Promise.all([
      Rider.find({}).sort({ createdAt: -1 }).lean(),
      Order.find({ 'assignedRider.riderId': { $ne: null } })
        .select('assignedRider status totalAmount paymentCollectedMode riderCashSettled createdAt')
        .lean(),
    ]);

    const enriched = riders.map((r) => {
      const myOrders = riderOrders.filter((o) => String(o.assignedRider?.riderId) === String(r._id));
      const todayOrders = myOrders.filter((o) => new Date(o.createdAt) >= startOfTodayIstInUtc);
      const delivered = myOrders.filter((o) => o.status === 'Delivered');
      const activeCount = myOrders.filter((o) => ['Pending', 'Cooking', 'Out for Delivery'].includes(o.status)).length;
      const cashCollected = delivered
        .filter((o) => o.paymentCollectedMode !== 'UPI')
        .reduce((s, o) => s + (o.totalAmount || 0), 0);
      const upiCollected = delivered
        .filter((o) => o.paymentCollectedMode === 'UPI')
        .reduce((s, o) => s + (o.totalAmount || 0), 0);
      const unsettledCash = delivered
        .filter((o) => o.paymentCollectedMode !== 'UPI' && !o.riderCashSettled)
        .reduce((s, o) => s + (o.totalAmount || 0), 0);

      return {
        ...r,
        todayCount: todayOrders.length,
        deliveredCount: delivered.length,
        activeCount,
        cashCollected,
        upiCollected,
        unsettledCash,
      };
    });

    res.json({ riders: enriched });
  } catch (err) {
    console.error('GET /api/admin/riders error:', err);
    res.status(500).json({ error: 'Failed to load riders.' });
  }
});

app.post('/api/admin/riders', requireAdmin, async (req, res) => {
  try {
    const { name, phone, vehicleNote } = req.body || {};
    const cleanName = typeof name === 'string' ? name.trim() : '';
    const cleanPhone = normalizeIndianPhone(phone);
    if (cleanName.length < 2 || !cleanPhone) {
      return res.status(400).json({ error: 'Valid rider name and 10-digit Indian phone are required.' });
    }
    const rider = await Rider.create({
      name: cleanName,
      phone: cleanPhone,
      vehicleNote: vehicleNote ? String(vehicleNote).trim() : 'Bike',
    });
    res.status(201).json({ rider });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Rider with this phone already exists.' });
    console.error('POST /api/admin/riders error:', err);
    res.status(500).json({ error: 'Failed to add rider.' });
  }
});

app.post('/api/admin/riders/:id/settle', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const result = await Order.updateMany(
      {
        'assignedRider.riderId': req.params.id,
        status: 'Delivered',
        riderCashSettled: false,
      },
      { $set: { riderCashSettled: true } }
    );
    res.json({ settledCount: result.modifiedCount || 0 });
  } catch (err) {
    console.error('POST /api/admin/riders/:id/settle error:', err);
    res.status(500).json({ error: 'Failed to settle rider cash.' });
  }
});

app.delete('/api/admin/riders/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const deleted = await Rider.findByIdAndDelete(req.params.id).lean();
    if (!deleted) return res.status(404).json({ error: 'Rider not found.' });
    res.json({ deletedId: req.params.id });
  } catch (err) {
    console.error('DELETE /api/admin/riders/:id error:', err);
    res.status(500).json({ error: 'Failed to delete rider.' });
  }
});

// --- PROFIT, CASH vs UPI & EXPENSES ANALYTICS (IST Timezone Aware) ---

app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
  try {
    const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
    const nowIst = new Date(Date.now() + IST_OFFSET_MS);
    const startOfTodayIstInUtc = new Date(
      Date.UTC(nowIst.getUTCFullYear(), nowIst.getUTCMonth(), nowIst.getUTCDate()) - IST_OFFSET_MS
    );
    const startOfMonthIstInUtc = new Date(
      Date.UTC(nowIst.getUTCFullYear(), nowIst.getUTCMonth(), 1) - IST_OFFSET_MS
    );

    const [deliveredOrders, allExpenses, statusCountsRaw] = await Promise.all([
      Order.find({ status: 'Delivered' })
        .select('subtotal discountAmount deliveryCharge totalAmount totalMakingCost paymentCollectedMode items createdAt')
        .lean(),
      Expense.find({}).select('amount expenseDate').lean(),
      Order.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
    ]);

    const summarize = (ordersList, expensesList) => {
      let foodSales = 0;
      let discountsGiven = 0;
      let deliveryChargesCollected = 0;
      let totalSales = 0;
      let totalMakingCost = 0;
      let cashSales = 0;
      let upiSales = 0;

      for (const ord of ordersList) {
        foodSales += ord.subtotal || 0;
        discountsGiven += ord.discountAmount || 0;
        deliveryChargesCollected += ord.deliveryCharge || 0;
        totalSales += ord.totalAmount || 0;
        totalMakingCost += ord.totalMakingCost || 0;
        if (ord.paymentCollectedMode === 'UPI') upiSales += ord.totalAmount || 0;
        else cashSales += ord.totalAmount || 0;
      }

      let totalExpenses = 0;
      for (const exp of expensesList) {
        totalExpenses += exp.amount || 0;
      }

      const grossProfit = totalSales - totalMakingCost;
      const netProfit = grossProfit - totalExpenses;
      const grossMarginPercent = totalSales > 0 ? Number(((grossProfit / totalSales) * 100).toFixed(1)) : 0;
      const marginPercent = totalSales > 0 ? Number(((netProfit / totalSales) * 100).toFixed(1)) : 0;

      return {
        deliveredCount: ordersList.length,
        foodSales,
        discountsGiven,
        deliveryChargesCollected,
        totalSales,
        cashSales,
        upiSales,
        totalMakingCost,
        grossProfit,
        grossMarginPercent,
        totalExpenses,
        netProfit,
        marginPercent,
      };
    };

    const todayOrders = deliveredOrders.filter((o) => new Date(o.createdAt) >= startOfTodayIstInUtc);
    const monthOrders = deliveredOrders.filter((o) => new Date(o.createdAt) >= startOfMonthIstInUtc);
    const todayExpenses = allExpenses.filter((e) => new Date(e.expenseDate) >= startOfTodayIstInUtc);
    const monthExpenses = allExpenses.filter((e) => new Date(e.expenseDate) >= startOfMonthIstInUtc);

    const itemMap = new Map();
    for (const ord of deliveredOrders) {
      for (const it of ord.items || []) {
        const key = it.nameEn || it.nameHi;
        if (!itemMap.has(key)) {
          itemMap.set(key, { nameHi: it.nameHi, nameEn: it.nameEn, qtySold: 0, revenue: 0, cost: 0, profit: 0 });
        }
        const entry = itemMap.get(key);
        const rev = (it.sellingPrice || 0) * (it.quantity || 0);
        const cst = (it.makingCost || 0) * (it.quantity || 0);
        entry.qtySold += it.quantity || 0;
        entry.revenue += rev;
        entry.cost += cst;
        entry.profit += rev - cst;
      }
    }
    const topItems = [...itemMap.values()].sort((a, b) => b.qtySold - a.qtySold).slice(0, 10);

    const statusCounts = {
      Pending: 0,
      Cooking: 0,
      'Out for Delivery': 0,
      Delivered: 0,
      Cancelled: 0,
    };
    for (const row of statusCountsRaw) {
      if (row._id in statusCounts) statusCounts[row._id] = row.count;
    }

    res.json({
      today: summarize(todayOrders, todayExpenses),
      month: summarize(monthOrders, monthExpenses),
      total: summarize(deliveredOrders, allExpenses),
      topItems,
      statusCounts,
    });
  } catch (err) {
    console.error('GET /api/admin/analytics error:', err);
    res.status(500).json({ error: 'Failed to compute analytics.' });
  }
});

// --- DAILY EXPENSES MANAGER ---

app.get('/api/admin/expenses', requireAdmin, async (req, res) => {
  try {
    const expenses = await Expense.find({}).sort({ expenseDate: -1, createdAt: -1 }).limit(150).lean();
    res.json({ expenses });
  } catch (err) {
    console.error('GET /api/admin/expenses error:', err);
    res.status(500).json({ error: 'Failed to load expenses.' });
  }
});

app.post('/api/admin/expenses', requireAdmin, async (req, res) => {
  try {
    const { title, category, amount, note, expenseDate } = req.body || {};
    const numAmount = Number(amount);
    if (!title || amount === undefined || !Number.isFinite(numAmount) || numAmount < 0) {
      return res.status(400).json({ error: 'Expense title and valid amount are required.' });
    }
    const allowedCats = ['Gas/Fuel', 'Ingredients', 'Packaging', 'Delivery/Petrol', 'Staff', 'Other'];
    const expense = await Expense.create({
      title: String(title).trim(),
      category: allowedCats.includes(category) ? category : 'Other',
      amount: numAmount,
      note: note ? String(note).trim() : '',
      expenseDate: expenseDate ? new Date(expenseDate) : new Date(),
    });
    res.status(201).json({ expense });
  } catch (err) {
    console.error('POST /api/admin/expenses error:', err);
    res.status(500).json({ error: 'Failed to add expense.' });
  }
});

app.delete('/api/admin/expenses/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const deleted = await Expense.findByIdAndDelete(req.params.id).lean();
    if (!deleted) return res.status(404).json({ error: 'Expense not found.' });
    res.json({ deletedId: req.params.id });
  } catch (err) {
    console.error('DELETE /api/admin/expenses/:id error:', err);
    res.status(500).json({ error: 'Failed to delete expense.' });
  }
});

// --- CUSTOMERS CRM DIRECTORY ---

app.get('/api/admin/customers', requireAdmin, async (req, res) => {
  try {
    const [agg, blockedDocs] = await Promise.all([
      Order.aggregate([
        { $sort: { createdAt: -1 } },
        {
          $group: {
            _id: '$phone',
            customerName: { $first: '$customerName' },
            lastAddress: { $first: '$address' },
            lastOrderAt: { $first: '$createdAt' },
            totalOrders: { $sum: 1 },
            deliveredOrders: { $sum: { $cond: [{ $eq: ['$status', 'Delivered'] }, 1, 0] } },
            cancelledOrders: { $sum: { $cond: [{ $eq: ['$status', 'Cancelled'] }, 1, 0] } },
            totalSpent: { $sum: { $cond: [{ $eq: ['$status', 'Delivered'] }, '$totalAmount', 0] } },
          },
        },
        { $sort: { lastOrderAt: -1 } },
        { $limit: 300 },
      ]),
      BlockedNumber.find({}).select('phone').lean(),
    ]);

    const blockedSet = new Set(blockedDocs.map((b) => b.phone));
    const customers = agg.map((c) => ({
      phone: c._id,
      customerName: c.customerName,
      lastAddress: c.lastAddress,
      lastOrderAt: c.lastOrderAt,
      totalOrders: c.totalOrders,
      deliveredOrders: c.deliveredOrders,
      cancelledOrders: c.cancelledOrders,
      totalSpent: c.totalSpent,
      isBlocked: blockedSet.has(c._id),
    }));

    res.json({ customers });
  } catch (err) {
    console.error('GET /api/admin/customers error:', err);
    res.status(500).json({ error: 'Failed to load customers.' });
  }
});

// --- COUPONS & PROMO OFFERS MANAGER ---

app.get('/api/admin/coupons', requireAdmin, async (req, res) => {
  try {
    const coupons = await Coupon.find({}).sort({ createdAt: -1 }).lean();
    res.json({ coupons });
  } catch (err) {
    console.error('GET /api/admin/coupons error:', err);
    res.status(500).json({ error: 'Failed to load coupons.' });
  }
});

app.post('/api/admin/coupons', requireAdmin, async (req, res) => {
  try {
    const {
      code,
      titleHi,
      titleEn,
      applyTarget,
      discountType,
      discountValue,
      minOrderAmount,
      maxDiscount,
      freeDeliveryIncluded,
      applicableCategories,
      applicableItemIds,
      usageLimit,
      perUserLimit,
      firstOrderOnly,
      showOnStorefront,
      expiresAt,
      isActive,
    } = req.body || {};
    const cleanCode = typeof code === 'string' ? code.trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '') : '';
    if (cleanCode.length < 3) {
      return res.status(400).json({ error: 'Coupon code must be at least 3 alphanumeric characters.' });
    }
    if (!['FLAT', 'PERCENT', 'FREE_DELIVERY'].includes(discountType)) {
      return res.status(400).json({ error: 'Invalid discount type.' });
    }

    const cleanTarget = ['ITEMS', 'FREE_DELIVERY', 'BOTH'].includes(applyTarget)
      ? applyTarget
      : discountType === 'FREE_DELIVERY'
      ? 'FREE_DELIVERY'
      : freeDeliveryIncluded
      ? 'BOTH'
      : 'ITEMS';

    const numVal = Math.max(0, Number(discountValue) || 0);
    if (cleanTarget !== 'FREE_DELIVERY' && discountType === 'PERCENT' && (numVal <= 0 || numVal > 100)) {
      return res.status(400).json({ error: 'Percentage discount must be between 1 and 100.' });
    }

    let parsedExpiry = null;
    if (expiresAt) {
      const dt = new Date(expiresAt);
      if (Number.isNaN(dt.getTime())) {
        return res.status(400).json({ error: 'Invalid expiry date.' });
      }
      parsedExpiry = dt;
    }

    const cleanCats = Array.isArray(applicableCategories)
      ? [...new Set(applicableCategories.map((c) => String(c).trim()).filter(Boolean))]
      : [];
    const cleanItemIds = Array.isArray(applicableItemIds)
      ? applicableItemIds.filter((id) => mongoose.Types.ObjectId.isValid(String(id)))
      : [];

    const coupon = await Coupon.create({
      code: cleanCode,
      titleHi: titleHi ? String(titleHi).trim().slice(0, 80) : '',
      titleEn: titleEn ? String(titleEn).trim().slice(0, 80) : '',
      applyTarget: cleanTarget,
      discountType: cleanTarget === 'FREE_DELIVERY' ? 'FREE_DELIVERY' : discountType,
      discountValue: cleanTarget === 'FREE_DELIVERY' ? 0 : numVal,
      minOrderAmount: Math.max(0, Number(minOrderAmount) || 0),
      maxDiscount: Math.max(0, Number(maxDiscount) || 0),
      freeDeliveryIncluded: cleanTarget === 'FREE_DELIVERY' || cleanTarget === 'BOTH' || Boolean(freeDeliveryIncluded),
      applicableCategories: cleanCats,
      applicableItemIds: cleanItemIds,
      usageLimit: Math.max(0, parseInt(usageLimit, 10) || 0),
      perUserLimit: Math.max(0, parseInt(perUserLimit, 10) || 0),
      firstOrderOnly: Boolean(firstOrderOnly),
      showOnStorefront: showOnStorefront !== undefined ? Boolean(showOnStorefront) : true,
      expiresAt: parsedExpiry,
      isActive: isActive !== undefined ? Boolean(isActive) : true,
    });
    res.status(201).json({ coupon });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Coupon code already exists.' });
    console.error('POST /api/admin/coupons error:', err);
    res.status(500).json({ error: 'Failed to create coupon.' });
  }
});

app.put('/api/admin/coupons/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const updates = {};
    if (req.body.code !== undefined) {
      const cleanCode = String(req.body.code || '').trim().toUpperCase().replace(/[^A-Z0-9_-]/g, '');
      if (cleanCode.length < 3) {
        return res.status(400).json({ error: 'Coupon code must be at least 3 alphanumeric characters.' });
      }
      updates.code = cleanCode;
    }
    if (req.body.applyTarget !== undefined && ['ITEMS', 'FREE_DELIVERY', 'BOTH'].includes(req.body.applyTarget)) {
      updates.applyTarget = req.body.applyTarget;
      updates.freeDeliveryIncluded = req.body.applyTarget === 'FREE_DELIVERY' || req.body.applyTarget === 'BOTH';
    }
    if (req.body.discountType !== undefined && ['FLAT', 'PERCENT', 'FREE_DELIVERY'].includes(req.body.discountType)) {
      updates.discountType = req.body.discountType;
    }
    if (req.body.isActive !== undefined) updates.isActive = Boolean(req.body.isActive);
    if (req.body.showOnStorefront !== undefined) updates.showOnStorefront = Boolean(req.body.showOnStorefront);
    if (req.body.firstOrderOnly !== undefined) updates.firstOrderOnly = Boolean(req.body.firstOrderOnly);
    if (req.body.freeDeliveryIncluded !== undefined && req.body.applyTarget === undefined) {
      updates.freeDeliveryIncluded = Boolean(req.body.freeDeliveryIncluded);
    }
    if (req.body.discountValue !== undefined) updates.discountValue = Math.max(0, Number(req.body.discountValue) || 0);
    if (req.body.minOrderAmount !== undefined) updates.minOrderAmount = Math.max(0, Number(req.body.minOrderAmount) || 0);
    if (req.body.maxDiscount !== undefined) updates.maxDiscount = Math.max(0, Number(req.body.maxDiscount) || 0);
    if (req.body.usageLimit !== undefined) updates.usageLimit = Math.max(0, parseInt(req.body.usageLimit, 10) || 0);
    if (req.body.perUserLimit !== undefined) updates.perUserLimit = Math.max(0, parseInt(req.body.perUserLimit, 10) || 0);
    if (req.body.titleHi !== undefined) updates.titleHi = String(req.body.titleHi).trim().slice(0, 80);
    if (req.body.titleEn !== undefined) updates.titleEn = String(req.body.titleEn).trim().slice(0, 80);
    if (Array.isArray(req.body.applicableCategories)) {
      updates.applicableCategories = [...new Set(req.body.applicableCategories.map((c) => String(c).trim()).filter(Boolean))];
    }
    if (Array.isArray(req.body.applicableItemIds)) {
      updates.applicableItemIds = req.body.applicableItemIds.filter((id) => mongoose.Types.ObjectId.isValid(String(id)));
    }
    if (req.body.expiresAt !== undefined) {
      updates.expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt) : null;
    }
    const coupon = await Coupon.findByIdAndUpdate(req.params.id, updates, { returnDocument: 'after' }).lean();
    if (!coupon) return res.status(404).json({ error: 'Coupon not found.' });
    res.json({ coupon });
  } catch (err) {
    if (err.code === 11000) return res.status(400).json({ error: 'Coupon code already exists.' });
    console.error('PUT /api/admin/coupons/:id error:', err);
    res.status(500).json({ error: 'Failed to update coupon.' });
  }
});

app.delete('/api/admin/coupons/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const deleted = await Coupon.findByIdAndDelete(req.params.id).lean();
    if (!deleted) return res.status(404).json({ error: 'Coupon not found.' });
    res.json({ deletedId: req.params.id });
  } catch (err) {
    console.error('DELETE /api/admin/coupons/:id error:', err);
    res.status(500).json({ error: 'Failed to delete coupon.' });
  }
});

// --- MENU & MARGIN MANAGER ---

app.get('/api/admin/menu', requireAdmin, async (req, res) => {
  try {
    const menu = await MenuItem.find({}).sort({ sortOrder: 1, createdAt: 1 }).lean();
    res.json({ menu });
  } catch (err) {
    console.error('GET /api/admin/menu error:', err);
    res.status(500).json({ error: 'Failed to fetch admin menu.' });
  }
});

app.post('/api/admin/menu', requireAdmin, async (req, res) => {
  try {
    const {
      nameHi,
      nameEn,
      descHi,
      descEn,
      category,
      sellingPrice,
      makingCost,
      imageUrl,
      inStock,
      stockCount,
      isVeg,
      isPopular,
      sortOrder,
    } = req.body || {};

    if (!nameHi || !nameEn || sellingPrice === undefined || makingCost === undefined) {
      return res.status(400).json({ error: 'Hindi name, English name, selling price, and making cost are required.' });
    }

    const numSelling = Number(sellingPrice);
    const numCost = Number(makingCost);
    if (!Number.isFinite(numSelling) || numSelling < 0 || !Number.isFinite(numCost) || numCost < 0) {
      return res.status(400).json({ error: 'Valid non-negative numbers are required for selling price and making cost.' });
    }

    let parsedStock = null;
    if (stockCount !== null && stockCount !== undefined && stockCount !== '') {
      const sInt = parseInt(stockCount, 10);
      if (!Number.isInteger(sInt) || sInt < 0) {
        return res.status(400).json({ error: 'Stock count must be a non-negative integer.' });
      }
      parsedStock = sInt;
    }

    const cleanCategory = category ? String(category).trim() : 'Snacks';
    const defaultSort = DEFAULT_CATEGORY_SORT_ORDER[cleanCategory] || 100;

    const item = await MenuItem.create({
      nameHi: String(nameHi).trim(),
      nameEn: String(nameEn).trim(),
      descHi: descHi ? String(descHi).trim() : '',
      descEn: descEn ? String(descEn).trim() : '',
      category: cleanCategory,
      sellingPrice: Math.max(0, numSelling),
      makingCost: Math.max(0, numCost),
      imageUrl: imageUrl ? String(imageUrl).trim() : '',
      inStock: parsedStock === 0 ? false : inStock !== undefined ? Boolean(inStock) : true,
      stockCount: parsedStock,
      isVeg: isVeg !== undefined ? Boolean(isVeg) : true,
      isPopular: isPopular !== undefined ? Boolean(isPopular) : false,
      sortOrder:
        sortOrder !== undefined && sortOrder !== null && sortOrder !== '' && Number.isFinite(Number(sortOrder))
          ? Number(sortOrder)
          : defaultSort,
    });

    res.status(201).json({ item });
  } catch (err) {
    console.error('POST /api/admin/menu error:', err);
    res.status(500).json({ error: 'Failed to create menu item.' });
  }
});

app.put('/api/admin/menu/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const updates = {};
    const {
      nameHi,
      nameEn,
      descHi,
      descEn,
      category,
      sellingPrice,
      makingCost,
      imageUrl,
      inStock,
      stockCount,
      isVeg,
      isPopular,
      sortOrder,
    } = req.body || {};

    if (nameHi !== undefined) updates.nameHi = String(nameHi).trim();
    if (nameEn !== undefined) updates.nameEn = String(nameEn).trim();
    if (descHi !== undefined) updates.descHi = String(descHi).trim();
    if (descEn !== undefined) updates.descEn = String(descEn).trim();
    if (category !== undefined) updates.category = String(category).trim();
    if (sellingPrice !== undefined) {
      const n = Number(sellingPrice);
      if (!Number.isFinite(n) || n < 0) return res.status(400).json({ error: 'Invalid sellingPrice.' });
      updates.sellingPrice = n;
    }
    if (makingCost !== undefined) {
      const n = Number(makingCost);
      if (!Number.isFinite(n) || n < 0) return res.status(400).json({ error: 'Invalid makingCost.' });
      updates.makingCost = n;
    }
    if (imageUrl !== undefined) updates.imageUrl = String(imageUrl).trim();
    if (inStock !== undefined) updates.inStock = Boolean(inStock);
    if (stockCount !== undefined) {
      if (stockCount === null || stockCount === '') {
        updates.stockCount = null;
      } else {
        const sInt = parseInt(stockCount, 10);
        if (!Number.isInteger(sInt) || sInt < 0) return res.status(400).json({ error: 'Invalid stockCount.' });
        updates.stockCount = sInt;
      }
    }
    if (isVeg !== undefined) updates.isVeg = Boolean(isVeg);
    if (isPopular !== undefined) updates.isPopular = Boolean(isPopular);
    if (sortOrder !== undefined && Number.isFinite(Number(sortOrder))) updates.sortOrder = Number(sortOrder);

    if (updates.stockCount === 0) {
      updates.inStock = false;
    } else if (updates.inStock === true && stockCount === undefined) {
      const existingItem = await MenuItem.findById(req.params.id).select('stockCount').lean();
      if (existingItem && existingItem.stockCount === 0) {
        updates.stockCount = null;
      }
    }

    const item = await MenuItem.findByIdAndUpdate(req.params.id, updates, { returnDocument: 'after' }).lean();
    if (!item) return res.status(404).json({ error: 'Menu item not found.' });

    res.json({ item });
  } catch (err) {
    console.error('PUT /api/admin/menu/:id error:', err);
    res.status(500).json({ error: 'Failed to update menu item.' });
  }
});

app.delete('/api/admin/menu/:id', requireAdmin, validateObjectId, async (req, res) => {
  try {
    const deleted = await MenuItem.findByIdAndDelete(req.params.id).lean();
    if (!deleted) return res.status(404).json({ error: 'Menu item not found.' });
    res.json({ deletedId: req.params.id });
  } catch (err) {
    console.error('DELETE /api/admin/menu/:id error:', err);
    res.status(500).json({ error: 'Failed to delete menu item.' });
  }
});

// --- STORE SETTINGS & BLOCKED NUMBERS ---

app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const [settings, blockedNumbers] = await Promise.all([
      getStoreSettings(),
      BlockedNumber.find({}).sort({ blockedAt: -1 }).lean(),
    ]);
    res.json({ settings, blockedNumbers });
  } catch (err) {
    console.error('GET /api/admin/settings error:', err);
    res.status(500).json({ error: 'Failed to fetch settings.' });
  }
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const {
      shopNameHi,
      shopNameEn,
      isOpen,
      deliveryCharge,
      freeDeliveryAbove,
      minOrderAmount,
      deliveryRadiusKm,
      openHoursHi,
      openHoursEn,
      supportPhone,
      upiId,
      announcementHi,
      announcementEn,
      timerTitleHi,
      timerTitleEn,
      timerMinutes,
      clearTimer,
    } = req.body || {};

    const updates = {};
    if (shopNameHi !== undefined) updates.shopNameHi = String(shopNameHi).trim();
    if (shopNameEn !== undefined) updates.shopNameEn = String(shopNameEn).trim();
    if (isOpen !== undefined) updates.isOpen = Boolean(isOpen);
    if (deliveryCharge !== undefined && Number.isFinite(Number(deliveryCharge))) {
      updates.deliveryCharge = Math.max(0, Number(deliveryCharge));
    }
    if (freeDeliveryAbove !== undefined && Number.isFinite(Number(freeDeliveryAbove))) {
      updates.freeDeliveryAbove = Math.max(0, Number(freeDeliveryAbove));
    }
    if (minOrderAmount !== undefined && Number.isFinite(Number(minOrderAmount))) {
      updates.minOrderAmount = Math.max(0, Number(minOrderAmount));
    }
    if (deliveryRadiusKm !== undefined && Number.isFinite(Number(deliveryRadiusKm))) {
      updates.deliveryRadiusKm = Math.max(0.5, Number(deliveryRadiusKm));
    }
    if (openHoursHi !== undefined) updates.openHoursHi = String(openHoursHi).trim();
    if (openHoursEn !== undefined) updates.openHoursEn = String(openHoursEn).trim();
    if (supportPhone !== undefined) updates.supportPhone = String(supportPhone).trim();
    if (upiId !== undefined) updates.upiId = String(upiId).trim();
    if (announcementHi !== undefined) updates.announcementHi = String(announcementHi).trim();
    if (announcementEn !== undefined) updates.announcementEn = String(announcementEn).trim();
    if (timerTitleHi !== undefined) updates.timerTitleHi = String(timerTitleHi).trim();
    if (timerTitleEn !== undefined) updates.timerTitleEn = String(timerTitleEn).trim();
    if (clearTimer === true) {
      updates.timerEndsAt = null;
    } else if (timerMinutes !== undefined && timerMinutes !== null && timerMinutes !== '') {
      const mins = Number(timerMinutes);
      if (Number.isFinite(mins)) {
        updates.timerEndsAt = mins > 0 ? new Date(Date.now() + Math.min(1440, mins) * 60000) : null;
      }
    }

    const settings = await StoreSettings.findOneAndUpdate(
      { key: 'default' },
      { $set: updates },
      { returnDocument: 'after', upsert: true }
    ).lean();

    res.json({ settings });
  } catch (err) {
    console.error('PUT /api/admin/settings error:', err);
    res.status(500).json({ error: 'Failed to save settings.' });
  }
});

app.post('/api/admin/blocked-numbers', requireAdmin, async (req, res) => {
  try {
    const cleanPhone = normalizeIndianPhone(req.body?.phone || '');
    if (!cleanPhone) {
      return res.status(400).json({ error: 'Please provide a valid 10-digit Indian mobile number.' });
    }
    const reason = req.body?.reason ? String(req.body.reason).trim() : 'Fake / Spam Order';

    const doc = await BlockedNumber.findOneAndUpdate(
      { phone: cleanPhone },
      { phone: cleanPhone, reason, blockedAt: new Date() },
      { returnDocument: 'after', upsert: true }
    ).lean();

    res.status(201).json({ blocked: doc });
  } catch (err) {
    console.error('POST /api/admin/blocked-numbers error:', err);
    res.status(500).json({ error: 'Failed to block number.' });
  }
});

app.delete('/api/admin/blocked-numbers/:phone', requireAdmin, async (req, res) => {
  try {
    const cleanPhone = normalizeIndianPhone(req.params.phone || '');
    if (!cleanPhone) return res.status(400).json({ error: 'Invalid phone number.' });
    await BlockedNumber.deleteOne({ phone: cleanPhone });
    res.json({ unblockedPhone: cleanPhone });
  } catch (err) {
    console.error('DELETE /api/admin/blocked-numbers error:', err);
    res.status(500).json({ error: 'Failed to unblock number.' });
  }
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON request body.' });
  }
  if (err && err.message && err.message.startsWith('CORS blocked')) {
    return res.status(403).json({ error: err.message });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ----------------------------------------------------------------------------
// 6. START SERVER & CONNECT MONGODB
// ----------------------------------------------------------------------------

async function startServer() {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    console.error('❌ MONGODB_URI is missing! Set it in .env or Render Environment Variables.');
    process.exit(1);
  }

  try {
    await mongoose.connect(mongoUri);
    console.log('✅ Connected to MongoDB Atlas.');
    await seedDatabaseIfEmpty();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Gaon Rasoi server running on port ${PORT}`);
      console.log(`🔒 Allowed CORS origins: ${allowedOrigins.length ? allowedOrigins.join(', ') : 'localhost only'}`);
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  startServer();
}

module.exports = { app, seedDatabaseIfEmpty };
