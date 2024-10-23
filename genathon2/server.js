const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const path = require('path');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL connection setup
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'analytics',
  password: 'postgres',
  port: 5432,
});

// Middleware setup
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
}));
app.use(flash());

// Set EJS as the templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => {
  const user = req.session.user || null; // Get the logged-in user from session
  res.render('index', { 
    messages: req.flash('info'), // Pass flash messages
    user: user // Pass user to template
  });
});

// Signup page
app.get('/signup', (req, res) => {
  res.render('signup', { messages: req.flash('info') });
});

// Signup route with validation
app.post(
  "/signup",
  [
    body("username").not().isEmpty().withMessage("Username is required"),
    body("email")
      .isEmail()
      .withMessage("Please enter a valid email")
      .custom(async (email) => {
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (user.rows.length > 0) {
          throw new Error("Email already in use");
        }
      }),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long")
      .matches(/[a-z]/).withMessage("Password must contain at least one lowercase letter")
      .matches(/[A-Z]/).withMessage("Password must contain at least one uppercase letter")
      .matches(/\d/).withMessage("Password must contain at least one number")
      .matches(/[\W_]/).withMessage("Password must contain at least one special character"),
    body("confirm_password")
      .custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error("Passwords do not match");
        }
        return true;
      })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash('info', errors.array().map(err => err.msg).join(", "));
      return res.redirect('/signup');
    }

    const { username, email, password } = req.body;

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
        [username, email, hashedPassword]
      );
      req.flash('info', 'Signup successful! You can log in now.');
      res.redirect('/login');
    } catch (err) {
      console.error(err.message);
      req.flash('info', 'An error occurred while signing up.');
      res.redirect('/signup');
    }
  }
);

// Login page
app.get('/login', (req, res) => {
  res.render('login', { messages: req.flash('info') });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const userResult = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = userResult.rows[0];

    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.user = user; // Store user in session

      // Save session and redirect to home page
      req.session.save((err) => {
        if (err) {
          console.error(err);
          req.flash('info', 'An error occurred during login.');
          return res.redirect('/login');
        }
        req.flash('info', 'Login successful!');
        res.redirect('/');
      });
    } else {
      req.flash('info', 'Invalid username or password');
      return res.redirect('/login');
    }
  } catch (err) {
    console.error(err.message);
    req.flash('info', 'An error occurred while logging in.');
    res.redirect('/login');
  }
});



// Logout route
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.redirect('/');
    }
    req.flash('info', 'Logout successful!');
    res.redirect('/');
  });
});

// Catch-all route for 404 errors
app.use((req, res) => {
  res.status(404).send('Sorry, that route does not exist.');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
