require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

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
});

// --------End of Generate schema with Mongoose Encryption--------

//Always use encrypt method before the mongoose model

// userSchema.plugin(encrypt, {
//   secret: process.env.SECRET,
//   encryptedFields: ['password'],
// });

const User = new mongoose.model('User', userSchema);

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

//Secure Password with Hashing Authentication
app.post('/register', (req, res) => {
  bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash,
    });
    newUser.save(function (err) {
      if (!err) {
        res.render('secrets');
      } else {
        res.send(err);
      }
    });
  });
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({ email: username }, function (err, foundUser) {
    if (!err) {
      if (foundUser) {
        bcrypt.compare(password, foundUser.password, function (err, result) {
          if (result === true) {
            res.render('secrets');
          }
        });
      }
    } else {
    }
  });
});

app.listen('3000', () => {
  console.log('Server started at port 3000');
});
