const passport = require("passport");
const WindowsLiveStrategy = require("passport-outlook").Strategy;
const { OUTLOOK_CLIENT_ID, OUTLOOK_CLIENT_SECRET } = process.env;
const User = require("../models/user");
const jwt = require("jsonwebtoken");

let port = process.env.PORT;
let auth =
  "https://swccoursedirectory.herokuapp.com/coursedirectory/auth/outlook/redirect";
if (port == null || port == "") {
  auth = "http://localhost:3000/coursedirectory/auth/outlook/redirect";
}

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id).then((user) => {
    done(null, user);
  });
});

passport.use(
  new WindowsLiveStrategy(
    {
      // options for outlook strategy
      clientID: OUTLOOK_CLIENT_ID,
      clientSecret: OUTLOOK_CLIENT_SECRET,
      callbackURL: auth,
    },
    async (accessToken, refresh_token, params, profile, done) => {
      try {
        var waadProfile = jwt.decode(params.id_token);
        const user = await User.findOne({
          email: waadProfile.preferred_username,
        });
        if (user) return done(null, user);
        const newUser = new User({
          email: waadProfile.preferred_username,
          outlookId: waadProfile.oid,
          name: waadProfile.name,
          accessToken: accessToken,
          // isverified: true,
        });
        if (refresh_token) newUser.refreshToken = refresh_token;

        const users = await User.find({});
        if (users.length == 0) {
          newUser.isAdmin = true;
        }

        await newUser.save();
        return done(null, newUser);
      } catch (error) {
        console.log(error.message);
      }
    }
  )
);
