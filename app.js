require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
// const encrypt = require("mongoose-encryption");                  //first tried this
// const md5 = require("md5");                                      //secondly tried this hashing technique
// const bcrypt = require("bcrypt");                                //Thirdly using this bcrypt type hashing combining with salting
// const saltRounds = 10;
const session = require("express-session");                                 // Fourthly using session and cookies
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;           //Fifthly Using OAuth google to login and verify
const findOrCreate = require("mongoose-findorcreate");


const app = express();

// console.log(process.env.SECRET);                                 //This is how to get values from .env file (because of encryption).

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://Archit:"+ process.env.MONGO_PASS +"@cluster0.fdjgc.mongodb.net/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
});

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

                                                                                                        //For encryption using mongoose-encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET , encryptedFields: ["password"]});                //This line must be before the mongoose.model line

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);

  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));



app.get("/", function (req, res) {
  res.render("home");
});
 
app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
 });

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req,res) {
  User.find({"secret": {$ne: null}}, function (err, foundUsers) { 
    if(err) {                                                                            // Render all the secrets on the secrets page
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }                                                                         
  });
});

app.get("/submit", function (req,res) {
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req,res) {
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function (err, foundUser) {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.get("/logout", function (req,res) {
  req.logout();
  res.redirect("/");
});


app.post("/register", function (req, res) {

  User.register({username: req.body.username}, req.body.password, function (err, user) {
    if(err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req,res,function () {
        res.redirect("/secrets");
      });
    }
  })


  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash,
  //   });
  
  //   newUser.save(function (err) {
  //     if (err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });
});

app.post("/login", function (req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function (err) {
    if(err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
        });
    }
  })


  // const username = req.body.username;
  // const password = req.body.password;

  // User.findOne({ email: username }, function (err, foundUser) {
  //   if (err) {
  //     console.log(err);
  //   } else {
  //     if (foundUser) {
  //       // if (foundUser.password === password) {
  //         bcrypt.compare(password, foundUser.password, function (err, result) {
  //           if(result === true) {
  //             res.render("secrets");
  //           }

  //         });
  //       // }
  //     }
  //   }
  // });
});

let port = process.env.PORT;
if(port == null || port == "") {
  port = 3000;
}

app.listen(port, function () {
  console.log("Server has started successfully");
});
