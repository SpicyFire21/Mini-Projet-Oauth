const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy; // ← corrige ici
const { oauthCallback } = require("./oauth.helper");
const jwt = require("jsonwebtoken");


passport.use(new DiscordStrategy({
    clientID: process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL: process.env.DISCORD_CALLBACK_URL,
    passReqToCallback: true,
    scope: ["identify", "email"]
}, async (req,accessToken, refreshToken, profile, done) => {
    try {
        const db = req.db; // récupère la DB injectée depuis la route

        const user = await oauthCallback({
            db,
            provider: "discord",
            providerId: profile.id,
            email: profile.email,
            name: profile.username,
            avatar: profile.avatar
                ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
                : null,
            accessToken,
            refreshToken
        });
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
            expiresIn: '7d'
        });

        done(null, { user, token });
    } catch (e) {
        done(e);
    }
}));
