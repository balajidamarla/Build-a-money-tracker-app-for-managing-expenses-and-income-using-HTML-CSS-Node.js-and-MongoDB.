const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect('mongodb://localhost/moneytracker', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// Create a schema for transactions
const transactionSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    description: String,
    amount: Number,
    type: String, // 'expense' or 'income'
    date: { type: Date, default: Date.now }
});

const Transaction = mongoose.model('Transaction', transactionSchema);

// Create a schema for users
const userSchema = new mongoose.Schema({
    username: String,
    password: String
});

userSchema.methods.validPassword = function (password) {
    return bcrypt.compareSync(password, this.password);
};

const User = mongoose.model('User', userSchema);

// Passport configuration
passport.use(new LocalStrategy(
    function (username, password, done) {
        User.findOne({ username: username }, function (err, user) {
            if (err) { return done(err); }
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            if (!user.validPassword(password)) {
                return done(null, false, { message: 'Incorrect password.' });
            }
            return done(null, user);
        });
    }
));

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

// Middleware
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

// API routes
app.get('/api/transactions', isAuthenticated, async (req, res) => {
    try {
        const transactions = await Transaction.find({ user: req.user._id });
        res.json(transactions);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/transactions', isAuthenticated, async (req, res) => {
    try {
        const newTransaction = new Transaction({
            user: req.user._id,
            description: req.body.description,
            amount: req.body.amount,
            type: req.body.type
        });

        await newTransaction.save();
        res.json(newTransaction);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Authentication routes
app.post('/api/auth/login', passport.authenticate('local'), (req, res) => {
    res.json({ authenticated: true, user: req.user });
});

app.get('/api/auth/logout', (req, res) => {
    req.logout();
    res.json({ loggedOut: true });
});

app.get('/api/auth/check', (req, res) => {
    res.json({ authenticated: req.isAuthenticated() });
});

app.get('/api/auth/user', (req, res) => {
    res.json(req.user);
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized' });
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
