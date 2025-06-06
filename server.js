const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = '@#fundi@secret123@key';

// ✅ Connexion à MySQL avec pool
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'fundi_v_002',
};

let pool;
(async () => {
  try {
    pool = await mysql.createPool(dbConfig);

    // Crée la table users si elle n'existe pas
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL,
        phone VARCHAR(20) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('artisans', 'particuliers') NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Base de données connectée et prête');
  } catch (err) {
    console.error('❌ Erreur de connexion à MySQL:', err);
  }
})();

// ✅ Route d'inscription
app.post(
  '/api/register',
  [
    body('username').notEmpty().withMessage('Le nom est requis'),
    body('phone')
      .matches(/^\+?[0-9]{7,15}$/)
      .withMessage('Numéro de téléphone invalide'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Le mot de passe doit contenir au moins 6 caractères'),
    body('role')
      .isIn(['artisans', 'particuliers'])
      .withMessage('Rôle invalide'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, phone, password, role } = req.body;

    try {
      const [existing] = await pool.query(
        'SELECT id FROM users WHERE phone = ?',
        [phone]
      );
      if (existing.length > 0) {
        return res
          .status(400)
          .json({ message: 'Ce numéro est déjà utilisé.' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      await pool.query(
        'INSERT INTO users (username, phone, password, role) VALUES (?, ?, ?, ?)',
        [username, phone, hashedPassword, role]
      );

      const token = jwt.sign({ phone, role }, JWT_SECRET, { expiresIn: '2d' });

      res.json({
        message: 'Inscription réussie',
        token,
        role,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Erreur serveur' });
    }
  }
);

// ✅ Route de connexion (login)
app.post('/api/login', async (req, res) => {
  const { phone, password } = req.body;

  if (!phone || !password) {
    return res.status(400).json({ message: 'Champs manquants' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE phone = ? LIMIT 1',
      [phone]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Utilisateur non trouvé' });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Mot de passe incorrect' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: '7d',
    });

    res.json({
      message: 'Connexion réussie',
      token,
      role: user.role,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

// ✅ Démarrage du serveur
app.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});
