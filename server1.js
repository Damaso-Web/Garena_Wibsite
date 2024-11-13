require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const bodyParser = require('body-parser');
const sgMail = require('@sendgrid/mail');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const mongoUri = process.env.MONGODB_URI || 'mongodb+srv://anabua70:shabuhaymo20@cluster0.l3yoq.mongodb.net/test?retryWrites=true&w=majority&ssl=true';
const client = new MongoClient(mongoUri);
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname + "/public"));
app.use('/node_modules', express.static("node_modules"));
app.use(helmet()); 
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// MongoDB setup 
let usersCollection;

async function connectToDatabase() {
  try {
    await client.connect();
    console.log('MongoDB connected');
    const database = client.db('test');
    usersCollection = database.collection('users');
  } catch (err) {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
  }
}

connectToDatabase();

// Mongoose Connection
mongoose.connect(mongoUri)
  .then(() => console.log('Mongoose connected'))
  .catch(err => console.log('Mongoose connection error:', err));

// Define Token Schema and Model
const tokenSchema = new mongoose.Schema({
  email: { type: String, required: true },
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 3600 },
});
const Token = mongoose.model('Token', tokenSchema);

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  emaildb: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' }, // Added role
  resetKey: String,
  resetExpires: Date,
});
const User = mongoose.model('User', userSchema);

// Session Middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your_session_secret',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: mongoUri }),
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Ensure cookies are sent only over HTTPS in production
    httpOnly: true,  // Prevent access to cookies via JavaScript
    sameSite: 'strict', // Prevent CSRF attacks
  },
}));

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  } else {
    return res.status(401).json({ success: false, message: 'Unauthorized access.' });
  }
}

// Role-based Access Control Middleware (Admin only)
function isAdmin(req, res, next) {
  const userId = req.session.userId;
  User.findById(userId).then(user => {
    if (user && user.role === 'admin') {
      return next();
    }
    return res.status(403).json({ message: 'Access denied: Admins only' });
  }).catch(() => {
    res.status(403).json({ message: 'Access denied' });
  });
}

// Hash Password Function
function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hashSync(password, saltRounds);
}

// Generate Random String
function generateRandomString(length) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
}

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send('Email is required');

  try {
    let token = await Token.findOne({ email });
    const resetToken = generateRandomString(32);

    if (token) {
      token.token = resetToken;
      await token.save();
    } else {
      await new Token({ email, token: resetToken }).save();
    }

    res.status(200).json({ message: 'Password reset token generated and saved' });
  } catch (error) {
    console.error('Error processing request:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Send Reset Code Email
async function sendResetCodeEmail(email, resetCode) {
  const msg = {
    to: email,
    from: 'adrianmarknabua5@gmail.com',
    subject: 'Your Password Reset Code',
    text: `Your password reset code is: ${resetCode}`,
    html: `<p>Your password reset code is:</p><h3>${resetCode}</h3>`,
  };
  try {
    await sgMail.send(msg);
    console.log(`Reset code sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Error sending reset code email');
  }
}

// Send Password Reset Code
app.post('/send-password-reset', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ emaildb: email });
    if (!user) return res.status(404).json({ message: 'No account with that email exists' });

    const resetCode = generateRandomString(6);
    user.resetKey = resetCode;
    user.resetExpires = new Date(Date.now() + 3600000); // 1-hour expiry
    await user.save();

    await sendResetCodeEmail(email, resetCode);
    res.json({ message: 'Password reset code sent', redirectUrl: '/reset-password.html' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ message: 'Error processing request' });
  }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
  const { resetKey, newPassword } = req.body;
  try {
    const user = await User.findOne({ resetKey, resetExpires: { $gt: new Date() } });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset key' });
    }

    user.password = hashPassword(newPassword);  // Hash the new password
    user.resetKey = null;
    user.resetExpires = null;
    await user.save();

    // Send success response
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ success: false, message: 'Error resetting password' });
  }
});

// Sign Up
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required' });
  }

  try {
    const existingUser = await usersCollection.findOne({ emaildb: email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: 'Password does not meet complexity requirements' });
    }

    const hashedPassword = hashPassword(password);
    await usersCollection.insertOne({ emaildb: email, password: hashedPassword, createdAt: new Date() });

    res.json({ success: true, message: 'Account created successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Login Rate Limiter
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 6, // Limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try again after 5 minutes.',
  handler: function (req, res, next, options) {
    res.status(options.statusCode).json({ success: false, message: options.message });
  }
});

// Login Route
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    if (!validator.isEmail(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    const user = await usersCollection.findOne({ emaildb: email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }

    req.session.userId = user._id;
    req.session.email = user.emaildb;

    res.json({ success: true, message: 'Login successful' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Dashboard Route - Protected by authentication middleware
app.get('/dashboard', isAuthenticated, (req, res) => {
  const userEmail = req.session.email;
  res.json({ message: `Welcome to your Dashboard, ${userEmail}!` });
});

// Admin Dashboard Route - Only admins can access
app.get('/admin-dashboard', isAuthenticated, isAdmin, (req, res) => {
  res.json({ message: 'Welcome to the admin dashboard!' });
});

app.listen(PORT, () => {
  const baseUrl = `http://localhost:${PORT}/index.html`;
  console.log(`\x1b[34mServer is running on port ${PORT}: ${baseUrl}\x1b[0m`);
});
