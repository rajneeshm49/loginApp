var express = require('express');
var router = express.Router();
var User = require('../models/user');

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

/* GET users listing. */
router.get('/login', function(req, res, next) {
  res.render('login');
});

router.get('/register', function(req, res, next) {
  res.render('register');
});

router.post('/register', function(req, res, next) {
  var name = req.body.name;
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;
  var password2 = req.body.password2;

  req.checkBody('name', 'Name cannot be empty').notEmpty();
  req.checkBody('username', 'Username cannot be empty').notEmpty();
  req.checkBody('email', 'Email cannot be empty').notEmpty();
  req.checkBody('password', 'Password cannot be empty').notEmpty();
  req.checkBody('password2', 'Passwords do not match').equals(password);

  var errors = req.validationErrors();

  if(errors) {
    res.render('register', {
      errors: errors
    });
  } else {
      var newUser = new User({
        name: name,
        username: username,
        email: email,
        password: password
      });

      User.createUser(newUser, function(err, user){
        if(err) {
          req.flash('error_msg','Registration failed. Please try again later');
          console.log(err);
        } else {
          req.flash('success_msg', 'Congratulations');
          res.redirect('/users/login');
          console.log(user);
        }    
      })
  }
});

passport.use(new LocalStrategy(
  function(username, password, done) {
    
    User.getByUsername(username, function(err, user) {
      if(err) {
        throw err;
      }
      if(!user) {
        return done(null, false, {message: 'Unknown User'});
      }
      User.comparePassword(password, user.password, function(err, isMatch) {
        if(err) {
          throw err;
        }
        console.log(isMatch);
        if(!isMatch) {
          return done(null, false, {message: 'Incorrect Password'});
        }
        return done(null, user, {message: 'Successfull'});
      })
    })
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

//Code to authenticate user
router.post('/login',
  passport.authenticate('local', {successRedirect: '/', failureRedirect: '/users/login', failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });

router.get('/logout',
  function(req, res) {
    req.logout();
    req.flash('success_msg', 'you are logged out');
    res.redirect('/users/login');
  });

module.exports = router;
