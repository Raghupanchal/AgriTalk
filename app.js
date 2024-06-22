const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const passport = require('passport');
const session = require('express-session');
const flash = require('connect-flash'); // Add connect-flash
const LocalStrategy = require('passport-local').Strategy;
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Session middleware setup
app.use(session({
    secret: process.env.SECRET_KEY, // Replace with your actual secret key for session
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Adjust secure setting based on your environment
}));

// Initialize connect-flash middleware
app.use(flash());

// Passport middleware setup
app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL database connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

// Middleware setup
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'public', 'uploads'));
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Passport local strategy setup
passport.use(new LocalStrategy(
    {
        usernameField: 'email', // Assuming email is used for username
        passwordField: 'password'
    },
    async (email, password, done) => {
        try {
            // Fetch user from the database
            const query = 'SELECT id, name, password FROM users WHERE email = $1';
            const result = await pool.query(query, [email]);

            if (result.rows.length === 0) {
                return done(null, false, { message: 'Invalid email or password' });
            }

            const user = result.rows[0];
            const match = await bcrypt.compare(password, user.password);

            if (match) {
                return done(null, user); // Authentication successful
            } else {
                return done(null, false, { message: 'Invalid email or password' });
            }
        } catch (error) {
            return done(error);
        }
    }
));

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user.id); // Serialize user ID into session
});

passport.deserializeUser(async (id, done) => {
    try {
        const query = 'SELECT id, name, email FROM users WHERE id = $1';
        const result = await pool.query(query, [id]);

        if (result.rows.length === 0) {
            return done(new Error('User not found'));
        }

        const user = result.rows[0];
        done(null, user); // Deserialize user from session
    } catch (error) {
        done(error);
    }
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/home', isAuthenticated, async (req, res) => {
    try {
        // Fetch posts from the database
        const query = 'SELECT title, content, image_url, users.name AS author_name FROM posts INNER JOIN users ON posts.author_id = users.id';
        const result = await pool.query(query);

        const posts = result.rows;

        res.render('home', { userName: req.user.name, posts }); // Render home page with posts data
    } catch (error) {
        console.error('Error fetching posts:', error);
        req.flash('error', 'Failed to load posts.');
        res.redirect('/');
    }
});

app.get('/new_post', isAuthenticated, (req, res) => {
    res.render('new_post');
});

// User registration endpoint
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Basic validation
        if (!name || !email || !password) {
            req.flash('error', 'Missing form data');
            return res.redirect('/register');
        }

        if (!validateEmail(email)) {
            req.flash('error', 'Invalid email format.');
            return res.redirect('/register');
        }

        if (!validatePassword(password)) {
            req.flash('error', 'Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.');
            return res.redirect('/register');
        }

        // Check if user already exists
        const checkUserQuery = 'SELECT id FROM users WHERE email = $1';
        const checkUserResult = await pool.query(checkUserQuery, [email]);

        if (checkUserResult.rows.length > 0) {
            req.flash('error', 'User already exists.');
            return res.redirect('/register');
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user into the database
        const insertUserQuery = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id';
        const insertUserResult = await pool.query(insertUserQuery, [name, email, hashedPassword]);

        req.flash('success', 'Registration successful. Please log in.');
        res.redirect('/'); // Redirect to login page after successful registration
    } catch (error) {
        console.error('Error registering user:', error);
        req.flash('error', 'Failed to register user.');
        res.redirect('/register');
    }
});

// User login endpoint
app.post('/login', passport.authenticate('local', {
    successRedirect: '/home', // Redirect on successful login
    failureRedirect: '/',     // Redirect on authentication failure
    failureFlash: true        // Enable flash messages for authentication failures
}));

// Create new post endpoint
app.post('/new_post', isAuthenticated, upload.single('image'), async (req, res) => {
    try {
        const { title, content } = req.body;
        const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
        const authorId = req.user.id; // Accessing user ID from req.user

        // Insert new post into the database
        const insertPostQuery = 'INSERT INTO posts (title, content, image_url, author_id) VALUES ($1, $2, $3, $4)';
        const values = [title, content, imageUrl, authorId];
        await pool.query(insertPostQuery, values);

        req.flash('success', 'Post created successfully.');
        res.redirect('/home'); // Redirect to the home page or post list
    } catch (error) {
        console.error('Error creating post:', error);
        req.flash('error', 'Failed to create post.');
        res.redirect('/new_post');
    }
});

// Logout endpoint
app.get('/logout', (req, res) => {
    req.logout(); // Passport.js function to clear login session
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            req.flash('error', 'Failed to logout');
            return res.redirect('/');
        }
        res.redirect('/login'); // Redirect to login page after logout
    });
});

// Function to validate email format
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Function to validate password format
function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
}

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    req.flash('error', 'Please log in to access this page.');
    res.redirect('/login'); // Redirect to login if not authenticated
}

// Start server
app.listen(port, () => {
    console.log(`Listening on port: ${port}`);
});
