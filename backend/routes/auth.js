const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('../config/passport');
const { findUserByEmail, findUserById, createLocalUser, comparePassword } = require('../models/User');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

const generateToken = (userId) => {
  return jwt.sign(
    { userId: userId.toString() },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );
};


router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const db = req.app.locals.db;

    // Validation
    if (!email || !password || !name) {
      return res.status(400).json({
        error: 'Données manquantes',
        message: 'Email, mot de passe et nom sont requis'
      });
    }

    // Validation password
    if (password.length < 6) {
      return res.status(400).json({
        error: 'Mot de passe invalide',
        message: 'Le mot de passe doit contenir au moins 6 caractères'
      });
    }

    // Vérifier si l'email existe déjà
    const existingUser = await findUserByEmail(db, email);
    if (existingUser) {
      return res.status(409).json({
        error: 'Email déjà utilisé',
        message: 'Un compte existe déjà avec cet email'
      });
    }

    // Créer l'utilisateur
    const user = await createLocalUser(db, { email, password, name });

    // Générer le token
    const token = generateToken(user._id);

    res.status(201).json({
      message: 'Compte créé avec succès',
      user: {
        _id: user._id,
        email: user.email,
        name: user.name,
        provider: user.provider
      },
      token,
      expiresIn: process.env.JWT_EXPIRES_IN || '1h'
    });
  } catch (error) {
    console.error('Erreur inscription:', error);
    res.status(500).json({
      error: 'Erreur serveur',
      message: error.message
    });
  }
});


router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const db = req.app.locals.db;

        // Validation des entrées
        if (!email || !password) {
            return res.status(400).json({
                error: 'Données manquantes',
                message: 'Email et mot de passe requis'
            });
        }

        // Récupération utilisateur
        const user = await findUserByEmail(db, email);
        if (!user) {
            return res.status(401).json({
                error: 'Identifiants invalides',
                message: 'Email ou mot de passe incorrect'
            });
        }

        // Vérification provider local obligatoire
        const hasLocalProvider = Array.isArray(user.providers)
            && user.providers.some(p => p.provider === 'local');

        if (!hasLocalProvider || !user.password) {
            return res.status(401).json({
                error: 'Connexion impossible',
                message: 'Ce compte utilise une authentification OAuth'
            });
        }

        // Vérification mot de passe
        const isPasswordValid = await comparePassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                error: 'Identifiants invalides',
                message: 'Email ou mot de passe incorrect'
            });
        }

        // Génération JWT
        const token = generateToken(user._id);

        // Réponse
        return res.json({
            message: 'Connexion réussie',
            user: {
                _id: user._id,
                email: user.email,
                name: user.name,
                providers: user.providers
            },
            token,
            expiresIn: process.env.JWT_EXPIRES_IN || '1h'
        });

    } catch (error) {
        console.error('Erreur login:', error);
        return res.status(500).json({
            error: 'Erreur serveur',
            message: error.message
        });
    }
});

router.get('/profile', authenticateToken, async (req, res) => {
  try {
    res.json({
      message: 'Profil utilisateur',
      user: req.user
    });
  } catch (error) {
    res.status(500).json({
      error: 'Erreur serveur',
      message: error.message
    });
  }
});

// GET /api/auth/users - Liste des utilisateurs (debug)
router.get('/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({
      message: 'Liste des utilisateurs',
      count: users.length,
      users
    });
  } catch (error) {
    res.status(500).json({
      error: 'Erreur serveur',
      message: error.message
    });
  }
});


router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get(
    "/google/callback",
    (req, res, next) => {
        // Injecter db dans la req pour qu'elle soit accessible dans la stratégie
        req.db = req.app.locals.db;
        next();
    },
    passport.authenticate("google", { session: false, failureRedirect: "/login" }),
    (req, res) => {
        // req.user contient { user, token } renvoyé par GoogleStrategy
        const token = req.user.token;
        res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    }
);

router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get(
    "/github/callback",
    (req, res, next) => {
        // Injecter db dans la req pour qu'elle soit accessible dans la stratégie
        req.db = req.app.locals.db;
        next();
    },  passport.authenticate("github", { session: false, failureRedirect: "/login" }),
    (req, res) => {
        // req.user contient { user, token } renvoyé par GoogleStrategy
        const token = req.user.token;
        res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    }
);

router.get("/discord", passport.authenticate("discord"));
router.get(
    "/discord/callback",
    (req, res, next) => {
        // Injecter db dans la req pour qu'elle soit accessible dans la stratégie
        req.db = req.app.locals.db;
        next();
    },  passport.authenticate("discord", { session: false, failureRedirect: "/login" }),
    (req, res) => {
        // req.user contient { user, token } renvoyé par GoogleStrategy
        const token = req.user.token;
        res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    }
);


module.exports = router;
