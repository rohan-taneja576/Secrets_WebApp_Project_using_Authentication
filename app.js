require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: 'Our little secret',
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.set('useCreateIndex', true);

// --------Normal way to generate schema--------
// const userSchema = {
//   email: String,
//   password: String,
// };
// --------End of Normal way to generate schema--------

// --------Generate schema with Mongoose Encryption--------

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  Secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// --------End of Generate schema with Mongoose Encryption--------

//Always use encrypt method before the mongoose model

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ['password'],
// });

const User = new mongoose.model('User', userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/auth/google/secrets',
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get('/', (req, res) => {
  res.render('home');
});

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);
app.get(
  '/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    //Successful authentication redirect to secrets
    res.redirect('/secrets');
  }
);

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});
app.get('/secrets', (req, res) => {
  User.find({ Secret: { $ne: null } }, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        res.render('secrets', { userWithSecrets: foundUser });
      }
    }
  });
});

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

app.get('/logout', (req, res) => {
  req.logOut();
  res.redirect('/');
});

//Important Note --> Remember when you update the code in your app.js and hit save that nodemon will restart  the server and whenever your server get restarted your cookies get deleted and your session gets restarted.

//Secure Password with Hashing Authentication
app.post('/register', (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect('/register');
      } else {
        passport.authenticate('local')(req, res, () => {
          res.redirect('/secrets');
        });
      }
    }
  );
  // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash,
  //   });
  //   newUser.save(function (err) {
  //     if (!err) {
  //       res.render('secrets');
  //     } else {
  //       res.send(err);
  //     }
  //   });
  // });
});

app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, err => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets');
      });
    }
  });

  // const username = req.body.username;
  // const password = req.body.password;
  // User.findOne({ email: username }, function (err, foundUser) {
  //   if (!err) {
  //     if (foundUser) {
  //       bcrypt.compare(password, foundUser.password, function (err, result) {
  //         if (result === true) {
  //           res.render('secrets');
  //         }
  //       });
  //     }
  //   } else {
  //   }
  // });
});

app.post('/submit', (req, res) => {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.Secret = submittedSecret;
        foundUser.save(function () {
          res.redirect('/secrets');
        });
      }
    }
  });
});

app.listen('3000', () => {
  console.log('Server started at port 3000');
});
