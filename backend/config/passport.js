const passport = require("passport");
const User = require("../models/User.js");

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

require("./strategies/google.strategy.js");
require("./strategies/github.strategy.js");
require("./strategies/discord.strategy.js");

module.exports = passport;
