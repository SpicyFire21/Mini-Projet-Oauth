const User = require("../../models/User.js");

async function oauthCallback({
                                 provider,
                                 providerId,
                                 email,
                                 name,
                                 avatar,
                                 accessToken,
                                 refreshToken,
                                 db
                             }) {
    // 1. Vérifier si l'utilisateur existe déjà avec ce provider
    let user = await User.findUserByProvider(db, provider, providerId);
    if (user) return user;

    // 2. Vérifier si un utilisateur existe déjà avec cet email
    if (email) {
        user = await User.findUserByEmail(db, email);
        if (user) {
            await db.collection("users").updateOne(
                { _id: user._id },
                { $push: { providers: { provider, providerId, avatar, accessToken, refreshToken } } }
            );
            return await User.findUserById(db, user._id);
        }
    }

    // 3. Créer un nouvel utilisateur
    const newUser = {
        email: email ? email.toLowerCase() : null,
        name,
        avatar,
        password: null,
        providers: [{ provider, providerId, avatar, accessToken, refreshToken }],
        createdAt: new Date()
    };
    const result = await db.collection("users").insertOne(newUser);
    newUser._id = result.insertedId;

    return newUser;
}

module.exports = { oauthCallback };
