const { ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");

/* =========================
   USERS
========================= */

async function findUserById(db, id) {
    return db.collection("users").findOne({ _id: new ObjectId(id) });
}

async function findUserByEmail(db, email) {
    return db.collection("users").findOne({ email: email.toLowerCase() });
}

async function findUserByProvider(db, provider, providerId) {
    return db.collection("users").findOne({
        providers: {
            $elemMatch: { provider, providerId }
        }
    });
}

/* =========================
   LOCAL AUTH
========================= */

async function createLocalUser(db, { email, password, name }) {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
        email: email.toLowerCase(),
        name,
        password: hashedPassword,
        providers: [{ provider: "local", providerId: null }],
        createdAt: new Date()
    };

    const result = await db.collection("users").insertOne(user);
    user._id = result.insertedId;

    return user;
}

async function comparePassword(password, hash) {
    return bcrypt.compare(password, hash);
}

/* =========================
   OAUTH (GENERIC)
========================= */

async function findOrCreateOAuthUser(db, {
    provider,
    providerId,
    email,
    name,
    picture,
    accessToken,
    refreshToken
}) {
    // 1. Provider déjà lié
    let user = await findUserByProvider(db, provider, providerId);
    if (user) return user;

    // 2. Email existant → lier le provider
    if (email) {
        user = await findUserByEmail(db, email);
        if (user) {
            await db.collection("users").updateOne(
                { _id: user._id },
                {
                    $push: {
                        providers: {
                            provider,
                            providerId,
                            picture,
                            accessToken,
                            refreshToken
                        }
                    }
                }
            );
            return findUserById(db, user._id);
        }
    }

    // 3. Nouvel utilisateur
    const newUser = {
        email: email ? email.toLowerCase() : null,
        name,
        password: null,
        providers: [{
            provider,
            providerId,
            picture,
            accessToken,
            refreshToken
        }],
        createdAt: new Date()
    };

    const result = await db.collection("users").insertOne(newUser);
    newUser._id = result.insertedId;

    return newUser;
}

module.exports = {
    findUserById,
    findUserByEmail,
    findUserByProvider,
    createLocalUser,
    comparePassword,
    findOrCreateOAuthUser
};
