require("dotenv").config();

const PORT = process.env.PORT;
const MONGODB_URL = process.env.MONGODB_URL;

const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

mongoose.connect(MONGODB_URL);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },    
    password: { type: String, required: true }
  })
);

const Message = mongoose.model(
  "Message",
  new Schema({
    text: { type: String, required: true },
    user: { type: Schema.Types.ObjectId, ref: "User", required: true },
    time_stamp: { type: Date, default: Date.now, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

const flash = require('connect-flash');

// Use session middleware
app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

// Initialize connect-flash
app.use(flash());

// Make flash messages available to all templates
app.use((req, res, next) => {
  res.locals.error = req.flash('error');
  next();
});

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/sign-up", (req, res) => res.render("sign-up-form"));

app.post("/sign-up", async (req, res, next) => {
  try {
    bcrypt.hash(req.body.password, 10, async (err, hashedPassword) => {
      if (err) {
        return next(err);
      }
      const user = new User({
        username: req.body.username,        
        password: hashedPassword 
      });
      const result = await user.save();
      res.redirect("/");
    });
  } catch (err) {
    return next(err);
  }
});

// Route to handle sending a message
app.post("/chat", async (req, res, next) => {
  try {
    if (!req.user) {
      return res.redirect("/");
    }
    const message = new Message({
      text: req.body.message,
      user: req.user._id
    });
    await message.save();
    return res.redirect("/chat");
  } catch (err) {
    return next(err);
  }
});

// Route to render messages based on membership status
app.get("/chat", async (req, res, next) => {
  try {
    if (!req.user) {
      return res.redirect("/");
    }

    // Fetch all messages and populate the user field
    const messages = await Message.find().populate("user").exec();
    res.render("chat", { user: req.user, messages });
  } catch (err) {
    next(err);
  }
});

app.post(
  "/log-in",
  (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        req.flash("error", info.message);
        return res.redirect("/");
      }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        return res.redirect("/chat");
      });
    })(req, res, next);
  }
);

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.listen(PORT, () => console.log(`app listening on port ${PORT}!`));