const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { oauthCallback } = require("./oauth.helper");
const jwt = require("jsonwebtoken");

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL,
            passReqToCallback: true, // IMPORTANT pour accéder à req
        },
        async (req, accessToken, refreshToken, profile, done) => {
            try {
                const db = req.db; // récupère la DB injectée depuis la route

                const user = await oauthCallback({
                    db,
                    provider: "google",
                    providerId: profile.id,
                    email: profile.emails?.[0]?.value,
                    name: profile.displayName,
                    avatar: profile.photos?.[0]?.value,
                    accessToken,
                    refreshToken,
                });

                const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
                    expiresIn: "7d",
                });

                done(null, { user, token });
            } catch (err) {
                done(err);
            }
        }
    )
);
