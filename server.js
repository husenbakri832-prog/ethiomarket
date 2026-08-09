require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const uploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ethiomarket';
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Error:', err.message));

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

const User = mongoose.model('User', new mongoose.Schema({
  name: String, email: { type: String, unique: true }, password: String, phone: String,
  wallet: { balance: { type: Number, default: 0 }, transactions: [Object] },
  role: { type: String, default: 'user' }
}, { timestamps: true }));

const Product = mongoose.model('Product', new mongoose.Schema({
  name: String, description: String, price: Number, image: String, category: String,
  isPremium: { type: Boolean, default: false },
  seller: mongoose.Schema.Types.ObjectId
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId, items: Array, total: Number,
  platformFee: Number, sellerPayout: Number, deliveryAddress: String,
  status: { type: String, default: 'pending' }
}, { timestamps: true }));

const Ticket = mongoose.model('Ticket', new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId, subject: String,
  status: { type: String, default: 'open' }, messages: [Object]
}, { timestamps: true }));

const Payment = mongoose.model('Payment', new mongoose.Schema({
  user: mongoose.Schema.Types.ObjectId, order: mongoose.Schema.Types.ObjectId,
  amount: Number, method: String, status: { type: String, default: 'pending' },
  transactionRef: String
}, { timestamps: true }));

const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET).id; next(); }
  catch (e) { res.status(401).json({ message: 'Invalid token' }); }
};

const adminAuth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const user = await User.findById(jwt.verify(token, JWT_SECRET).id);
    if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Admin access denied' });
    req.user = user._id; next();
  } catch (e) { res.status(401).json({ message: 'Invalid token' }); }
};

app.post('/api/auth/register', async (req, res) => {
  try {
    let user = await User.findOne({ email: req.body.email });
    if (user) return res.status(400).json({ message: 'User already exists' });
    const hashed = await bcrypt.hash(req.body.password, 10);
    user = new User({
      name: req.body.name, email: req.body.email, password: hashed, phone: req.body.phone,
      role: req.body.email === 'admin@ethiomarket.com' ? 'admin' : 'user'
    });
    await user.save();
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { _id: user._id, name: user.name, email: user.email } });
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user || !(await bcrypt.compare(req.body.password, user.password)))
      return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { _id: user._id, name: user.name, email: user.email } });
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/products', async (req, res) => {
  try {
    let products = await Product.find();
    if (products.length === 0) {
      products = await Product.insertMany([
        { name: 'Habesha Dress', description: 'Traditional handwoven cotton dress', price: 2200, image: '👗', category: 'Fashion' },
        { name: 'Wireless Headphones', description: 'Bluetooth 5.3, 40h battery', price: 3400, image: '🎧', category: 'Electronics' },
        { name: 'Yirgacheffe Coffee 1kg', description: 'Freshly roasted, fruity & floral', price: 450, image: '☕', category: 'Food' },
        { name: 'Mesob Basket', description: 'Handwoven serving basket', price: 340, image: '🧺', category: 'Home' },
        { name: 'Sheba Gold Honey', description: 'Pure raw highland honey', price: 280, image: '🍯', category: 'Food' },
        { name: 'Opal Ring', description: 'Ethiopian opal, sterling silver', price: 2100, image: '💍', category: 'Fashion' }
      ]);
    }
    res.json(products);
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/products', auth, upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, category } = req.body;
    if (!name || !price) return res.status(400).json({ message: 'Name and price are required' });
    let image = req.body.image || '📦';
    if (req.file) image = '/uploads/' + req.file.filename;
    const product = new Product({ name, description: description || '', price: Number(price), image, category: category || 'General', seller: req.user });
    await product.save();
    res.json(product);
  } catch (e) { res.status(500).json({ message: 'Failed to create product' }); }
});

app.post('/api/orders', auth, async (req, res) => {
  try {
    const { items, total, deliveryAddress } = req.body;
    const platformFee = total * 0.05;
    const order = new Order({ user: req.user, items, total, deliveryAddress, platformFee, sellerPayout: total - platformFee, status: 'pending' });
    await order.save();
    res.json(order);
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/orders', auth, async (req, res) => {
  try { res.json(await Order.find({ user: req.user }).sort('-createdAt')); }
  catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.post('/api/chat', auth, async (req, res) => {
  try {
    const lowerMsg = req.body.message.toLowerCase();
    let aiResponse = '', actionTaken = false;

    if (lowerMsg.includes('cancel')) {
      const order = await Order.findOne({ user: req.user, status: 'pending' }).sort('-createdAt');
      if (order) {
        order.status = 'cancelled'; await order.save();
        await User.findByIdAndUpdate(req.user, { $inc: { 'wallet.balance': order.total } });
        aiResponse = `✅ I cancelled your order and refunded ETB ${order.total} to your wallet.`;
        actionTaken = true;
      } else aiResponse = '❌ No pending orders to cancel.';
    }
    else if (lowerMsg.includes('update address to')) {
      const newAddress = req.body.message.split('update address to')[1].trim();
      const order = await Order.findOne({ user: req.user, status: 'pending' }).sort('-createdAt');
      if (order) { order.deliveryAddress = newAddress; await order.save(); aiResponse = '✅ Delivery address updated to: ' + newAddress; actionTaken = true; }
      else aiResponse = '❌ No pending order found.';
    }
    else if (lowerMsg.includes('address')) {
      aiResponse = "📍 Reply with: 'Update address to [Your New Address]'";
    }
    else if (lowerMsg.includes('status') || lowerMsg.includes('where is')) {
      const order = await Order.findOne({ user: req.user }).sort('-createdAt');
      aiResponse = order ? `📦 Your latest order #${order._id.slice(-6)} is: ${order.status.toUpperCase()}.` : "You don't have orders yet!";
    }
    else if (lowerMsg.includes('otp') || lowerMsg.includes('code')) {
      aiResponse = '📱 A new OTP sent to your phone. (Mock OTP: 1234)'; actionTaken = true;
    }
    else if (lowerMsg.includes('human') || lowerMsg.includes('support') || lowerMsg.includes('agent')) {
      const ticket = new Ticket({ user: req.user, subject: 'Escalated from AI Chat', messages: [{ sender: 'user', text: req.body.message }] });
      await ticket.save();
      aiResponse = `🎫 Support ticket created! ID #${ticket._id.slice(-6)}. A human agent will help you soon.`;
      actionTaken = true;
    }
    else {
      aiResponse = "👋 Selam! I am EthioMarket AI. I can:\n• Cancel orders\n• Update delivery address\n• Check order status\n• Resend OTP\n• Connect you to human support\nWhat do you need?";
    }
    res.json({ reply: aiResponse, actionTaken });
  } catch (e) { res.status(500).json({ reply: 'Sorry, my AI brain hit an error.' }); }
});

app.post('/api/payments/initialize', auth, async (req, res) => {
  try {
    const { orderId, method } = req.body;
    const order = await Order.findById(orderId);
    if (!order) return res.status(404).json({ message: 'Order not found' });
    const payment = new Payment({ user: req.user, order: orderId, amount: order.total, method, transactionRef: 'TX-' + Date.now() });
    await payment.save();

    if (method === 'chapa' && process.env.CHAPA_SECRET_KEY) {
      const chapaRes = await fetch('https://api.chapa.co/v1/transaction/initialize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.CHAPA_SECRET_KEY}` },
        body: JSON.stringify({
          amount: order.total, currency: 'ETB', email: 'customer@ethiomarket.com',
          first_name: 'Ethio', last_name: 'Market', tx_ref: payment.transactionRef,
          callback_url: `${req.protocol}://${req.get('host')}/api/payments/chapa-callback`,
          return_url: `${req.protocol}://${req.get('host')}/`
        })
      });
      const chapaData = await chapaRes.json();
      if (chapaData.status === 'success') return res.json({ checkout_url: chapaData.data.checkout_url, paymentId: payment._id });
      return res.status(400).json({ message: 'Chapa initialization failed' });
    }
    res.json({ paymentId: payment._id, simulation: true, message: `${method.toUpperCase()} payment initiated.` });
  } catch (e) { res.status(500).json({ message: 'Payment initialization failed' }); }
});

app.post('/api/payments/verify/:paymentId', auth, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.paymentId);
    if (!payment) return res.status(404).json({ message: 'Payment not found' });
    payment.status = 'success'; await payment.save();
    await Order.findByIdAndUpdate(payment.order, { status: 'shipped' });
    res.json({ message: 'Payment successful!', status: 'success' });
  } catch (e) { res.status(500).json({ message: 'Verification failed' }); }
});

app.get('/api/payments/chapa-callback', async (req, res) => {
  try {
    const verifyRes = await fetch(`https://api.chapa.co/v1/transaction/verify/${req.query.tx_ref}`, {
      headers: { 'Authorization': `Bearer ${process.env.CHAPA_SECRET_KEY}` }
    });
    const data = await verifyRes.json();
    if (data.status === 'success') {
      const payment = await Payment.findOne({ transactionRef: req.query.tx_ref });
      if (payment) { payment.status = 'success'; await payment.save(); await Order.findByIdAndUpdate(payment.order, { status: 'shipped' }); }
    }
    res.redirect('/');
  } catch (e) { res.redirect('/'); }
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const totalOrders = await Order.countDocuments();
    const totalUsers = await User.countDocuments();
    const openTickets = await Ticket.countDocuments({ status: 'open' });
    const agg = await Order.aggregate([{ $group: { _id: null, totalRevenue: { $sum: '$platformFee' }, totalSales: { $sum: '$total' } } }]);
    res.json({ totalOrders, totalUsers, openTickets, totalRevenue: agg[0]?.totalRevenue || 0, totalSales: agg[0]?.totalSales || 0 });
  } catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/orders', adminAuth, async (req, res) => {
  try { res.json(await Order.find().populate('user', 'name email').sort('-createdAt')); }
  catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/api/admin/tickets', adminAuth, async (req, res) => {
  try { res.json(await Ticket.find().populate('user', 'name email').sort('-createdAt')); }
  catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.put('/api/admin/tickets/:id/close', adminAuth, async (req, res) => {
  try { res.json(await Ticket.findByIdAndUpdate(req.params.id, { status: 'closed' }, { new: true })); }
  catch (e) { res.status(500).json({ message: 'Server error' }); }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 EthioMarket running at http://localhost:${PORT}`));
