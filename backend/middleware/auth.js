const jwt = require('jsonwebtoken');
const { findUserById } = require('../models/User');

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];
        console.log(authHeader)
        console.log(token)
        if (!token) {
            return res.status(401).json({
                error: 'Access token requis',
                message: 'Authentification requise'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const db = req.app.locals.db;
        const user = await findUserById(db, decoded.userId);

        if (!user) {
            return res.status(404).json({
                error: 'Utilisateur non trouvé'
            });
        }

        // suppression du mot de passe
        delete user.password;

        req.user = user;
        next();

    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expiré'
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(403).json({
                error: 'Token invalide'
            });
        }

        return res.status(500).json({
            error: 'Erreur serveur',
            message: error.message
        });
    }
};

module.exports = { authenticateToken };
