const passport = require("passport");
const WindowsLiveStrategy = require("passport-azure-ad-oauth2").Strategy;
const { OUTLOOK_CLIENT_ID, OUTLOOK_CLIENT_SECRET, BASEURL } = process.env;
const User = require("../models/user");
const jwt = require("jsonwebtoken");

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
      callbackURL: `${BASEURL}/auth/outlook/redirect`,
    },
    async (accessToken, refresh_token, params, profile, done) => {
      try {
        var waadProfile = jwt.decode(params.id_token);
        const user = await User.findOne({
          email: waadProfile.upn,
        });
        if (user) return done(null, user);
        const newUser = new User({
          email: waadProfile.upn,
          outlookId: waadProfile.oid,
          username: waadProfile.name,
          accessToken: accessToken,
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
