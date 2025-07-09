require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuration Multer pour le stockage des fichiers
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || '@#fundi@secret123@key';
const DAILY_API_KEY = process.env.DAILY_API_KEY || "f8c3105e5b5a90fe7029c35916fcdc87c3ffeeceddd9ec3f9b7b23ee4daf41d4";

// Configuration de la base de données
const dbConfig = {
  host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
  user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.MYSQLDATABASE || process.env.DB_NAME || 'fundi_v_003_1',
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};
let pool;

// Initialisation de la base de données
(async () => {
  try {
    pool = await mysql.createPool(dbConfig);

    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(100) NOT NULL,
      phone VARCHAR(20) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role ENUM('artisans', 'particuliers') NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS artisan_jobs (
      id INT AUTO_INCREMENT PRIMARY KEY,
      artisan_id INT NOT NULL,
      job VARCHAR(100) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (artisan_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS artisan_info (
      id INT AUTO_INCREMENT PRIMARY KEY,
      artisan_id INT NOT NULL,
      profile_image VARCHAR(255),
      cover_image VARCHAR(255),
      bio_description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (artisan_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS publications (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      uri VARCHAR(255) NOT NULL,
      description TEXT,
      type ENUM('image', 'video') NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      likes INT DEFAULT 0,
      views INT DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS publication_likes (
      id INT AUTO_INCREMENT PRIMARY KEY,
      publication_id INT NOT NULL,
      user_id INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (publication_id) REFERENCES publications(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE KEY (publication_id, user_id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS devis (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT NOT NULL,
      address TEXT,
      phone VARCHAR(20),
      preferred_date VARCHAR(50),
      budget VARCHAR(50),
      type ENUM('urgent', 'standard') DEFAULT 'standard',
      status ENUM('pending', 'responded', 'completed') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS devis_responses (
      id INT AUTO_INCREMENT PRIMARY KEY,
      devis_id INT NOT NULL,
      artisan_id INT NOT NULL,
      price VARCHAR(50) NOT NULL,
      estimated_time VARCHAR(50) NOT NULL,
      message TEXT,
      status ENUM('pending', 'accepted', 'rejected') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (devis_id) REFERENCES devis(id) ON DELETE CASCADE,
      FOREIGN KEY (artisan_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS calls (
      id INT AUTO_INCREMENT PRIMARY KEY,
      caller_id INT NOT NULL,
      artisan_id INT NOT NULL,
      room_name VARCHAR(255) NOT NULL,
      room_url VARCHAR(255) NOT NULL,
      status ENUM('ringing', 'ongoing', 'completed', 'missed', 'rejected') NOT NULL,
      started_at DATETIME,
      ended_at DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (caller_id) REFERENCES users(id),
      FOREIGN KEY (artisan_id) REFERENCES users(id)
    )`);

    await pool.query(`CREATE TABLE IF NOT EXISTS conversations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user1_id INT NOT NULL,
  user2_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE KEY unique_conversation (user1_id, user2_id)
)`);

    await pool.query(`CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  conversation_id INT NOT NULL,
  sender_id INT NOT NULL,
  content TEXT NOT NULL,
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
)`);



    console.log('✅ Base de données initialisée avec succès');
  } catch (err) {
    console.error('❌ Erreur lors de l\'initialisation de la base de données:', err);
    process.exit(1);
  }
})();

const server = http.createServer(app);
const io = new Server(server, { 
  cors: { 
    origin: process.env.CORS_ORIGIN || '*', 
    methods: ['GET', 'POST']
  } 
});

// Gestion des utilisateurs connectés
const onlineUsers = new Map(); // { userId: socketId }

io.on('connection', (socket) => {
  console.log(`🧩 Client connecté: ${socket.id}`);

  // Associer un userId à la connexion
  socket.on('register', (userId) => {
    onlineUsers.set(userId, socket.id);
    socket.join(`user-${userId}`);
    console.log(`🔗 Utilisateur ${userId} enregistré (SocketID: ${socket.id})`);
  });

  // Gestion des appels
  socket.on('accept-call', async ({ callId }) => {
    const [call] = await pool.query(
      'SELECT caller_id, room_url FROM calls WHERE id = ?',
      [callId]
    );
    
    if (call.length) {
      io.to(`user-${call[0].caller_id}`).emit('call-accepted', {
        callId,
        roomUrl: call[0].room_url
      });
    }
  });

  socket.on('reject-call', async ({ callId }) => {
    const [call] = await pool.query(
      'SELECT caller_id FROM calls WHERE id = ?',
      [callId]
    );
    
    if (call.length) {
      await pool.query(
        `UPDATE calls SET status = 'rejected', ended_at = NOW() 
        WHERE id = ?`,
        [callId]
      );
      io.to(`user-${call[0].caller_id}`).emit('call-rejected', { callId });
    }
  });

  socket.on('disconnect', () => {
    // Trouver et supprimer l'utilisateur déconnecté
    for (const [userId, sockId] of onlineUsers.entries()) {
      if (sockId === socket.id) {
        onlineUsers.delete(userId);
        console.log(`👋 Utilisateur ${userId} déconnecté`);
        break;
      }
    }
  });
});

// Middleware d'authentification amélioré
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: 'Token d\'authentification manquant' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ 
        success: false,
        error: 'Token invalide ou expiré' 
      });
    }
    req.user = user;
    next();
  });
}

// Middleware pour vérifier le rôle
function checkRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ 
        success: false,
        error: `Accès réservé aux ${role}` 
      });
    }
    next();
  };
}

/*********************************
 *          ROUTES API           *
 *********************************/

// ... [Vos routes existantes: login, register, artisan/job, artisan/info, uploadMedia, publications, devis...]

app.post('/api/login', [
  body('phone').notEmpty().withMessage('Le numéro de téléphone est requis'),
  body('password').notEmpty().withMessage('Le mot de passe est requis')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { phone, password } = req.body;
  
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE phone = ?', [phone]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Mot de passe incorrect' });
    }

    const [jobRows] = await pool.query('SELECT job FROM artisan_jobs WHERE artisan_id = ?', [user.id]);
    const [infoRows] = await pool.query('SELECT * FROM artisan_info WHERE artisan_id = ?', [user.id]);

    const token = jwt.sign(
      { 
        id: user.id, 
        role: user.role, 
        username: user.username 
      }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({ 
      token,
     
      id: user.id,
      username: user.username,
      role: user.role,
      job: jobRows[0]?.job,
      profileImage: infoRows[0]?.profile_image,
      coverImage: infoRows[0]?.cover_image,
      bio: infoRows[0]?.bio_description
     
    });
  } catch (err) {
    console.error('Erreur lors de la connexion:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post(
  '/api/register',
  [
    body('username').notEmpty().trim().withMessage('Le nom est requis'),
    body('phone')
      .notEmpty()
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
      return res.status(400).json({ 
        success: false,
        errors: errors.array().map(err => err.msg) 
      });
    }

    const { username, phone, password, role } = req.body;

    try {
      // Vérification si le numéro existe déjà
      const [existing] = await pool.query(
        'SELECT id FROM users WHERE phone = ?',
        [phone]
      );
      
      if (existing.length > 0) {
        return res.status(409).json({ 
          success: false,
          message: 'Ce numéro de téléphone est déjà utilisé' 
        });
      }

      // Hashage du mot de passe
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insertion de l'utilisateur
      const [result] = await pool.query(
        'INSERT INTO users (username, phone, password, role) VALUES (?, ?, ?, ?)',
        [username, phone, hashedPassword, role]
      );

      // Création du token JWT
      const token = jwt.sign(
        { 
          id: result.insertId, 
          phone, 
          role,
          username 
        }, 
        JWT_SECRET, 
        { expiresIn: '7d' }
      );

      // Réponse réussie
      res.status(201).json({
        success: true,
        message: 'Inscription réussie',
        token,
        
          id: result.insertId,
          username,
          phone,
          role
       
      });

    } catch (err) {
      console.error('Erreur lors de l\'inscription:', err);
      res.status(500).json({ 
        success: false,
        message: 'Erreur lors de l\'inscription',
        error: err.message 
      });
    }
  }
);

/**
 * @route POST /api/artisan/job
 * @description Ajouter ou mettre à jour le métier d'un artisan
 * @access Authentifié (artisans seulement)
 */
app.post(
  '/api/artisan/job',
  authenticateToken,
  [
    body('job')
      .notEmpty().trim().withMessage('Le métier est requis')
      .isLength({ max: 100 }).withMessage('Le métier ne doit pas dépasser 100 caractères')
  ],
  async (req, res) => {
    // Vérification que l'utilisateur est bien un artisan
    if (req.user.role !== 'artisans') {
      return res.status(403).json({ 
        success: false,
        error: 'Accès refusé - Réservé aux artisans' 
      });
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        success: false,
        errors: errors.array().map(err => err.msg) 
      });
    }

    const { job } = req.body;
    const artisanId = req.user.id;

    try {
      // Vérifier si l'artisan a déjà un métier enregistré
      const [existingJob] = await pool.query(
        'SELECT id FROM artisan_jobs WHERE artisan_id = ?',
        [artisanId]
      );

      if (existingJob.length > 0) {
        // Mise à jour du métier existant
        await pool.query(
          'UPDATE artisan_jobs SET job = ? WHERE artisan_id = ?',
          [job, artisanId]
        );
      } else {
        // Insertion d'un nouveau métier
        await pool.query(
          'INSERT INTO artisan_jobs (artisan_id, job) VALUES (?, ?)',
          [artisanId, job]
        );
      }

      res.json({
        success: true,
        message: 'Métier mis à jour avec succès',
        job
      });

    } catch (err) {
      console.error('Erreur lors de la mise à jour du métier:', err);
      res.status(500).json({ 
        success: false,
        error: 'Erreur lors de la mise à jour du métier',
        details: err.message 
      });
    }
  }
);
app.post('/api/artisan/info', 
  authenticateToken,
  upload.fields([
    { name: 'profile_image', maxCount: 1 },
    { name: 'cover_image', maxCount: 1 }
  ]), 
  async (req, res) => {
    const { bio_description } = req.body;
    const userId = req.user.id;
    const profileImage = req.files['profile_image']?.[0]?.filename;
    const coverImage = req.files['cover_image']?.[0]?.filename;

    try {
      const [existingInfo] = await pool.query('SELECT * FROM artisan_info WHERE artisan_id = ?', [userId]);
      
      if (existingInfo.length > 0) {
        await pool.query(
          `UPDATE artisan_info 
          SET 
            profile_image = COALESCE(?, profile_image),
            cover_image = COALESCE(?, cover_image),
            bio_description = ?
          WHERE artisan_id = ?`,
          [profileImage, coverImage, bio_description, userId]
        );
      } else {
        await pool.query(
          'INSERT INTO artisan_info (artisan_id, profile_image, cover_image, bio_description) VALUES (?, ?, ?, ?)',
          [userId, profileImage, coverImage, bio_description]
        );
      }

      const [updatedInfo] = await pool.query(`
        SELECT * FROM artisan_info 
        WHERE artisan_id = ?
      `, [userId]);
      
      res.json({ 
        message: 'Informations mises à jour',
        info: updatedInfo[0]
      });
    } catch (err) {
      console.error('Erreur lors de la mise à jour des informations:', err);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

app.get('/api/artisan/info/:id', async (req, res) => {
  const artisanId = req.params.id;
  
  try {
    const [rows] = await pool.query(`
      SELECT ai.*, u.username, aj.job 
      FROM artisan_info ai
      LEFT JOIN users u ON ai.artisan_id = u.id
      LEFT JOIN artisan_jobs aj ON ai.artisan_id = aj.artisan_id
      WHERE ai.artisan_id = ?
    `, [artisanId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Artisan non trouvé' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Erreur lors de la récupération des informations:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Middleware pour vérifier les uploads
app.use('/api/uploadMedia', (req, res, next) => {
  console.log('Headers reçus:', req.headers);
  console.log('Content-Type:', req.headers['content-type']);
  next();
});

// Route d'upload corrigée
app.post('/api/uploadMedia', 
  authenticateToken,
  (req, res, next) => {
    // Middleware personnalisé pour parser multipart/form-data
    upload.single('file')(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        console.error('Erreur Multer:', err);
        return res.status(400).json({ 
          error: err.code === 'LIMIT_FILE_SIZE' 
            ? 'Le fichier dépasse la taille maximale de 50MB' 
            : 'Erreur lors du téléchargement du fichier'
        });
      } else if (err) {
        console.error('Erreur inconnue:', err);
        return res.status(500).json({ error: 'Erreur serveur' });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      if (!req.file) {
        console.log('Aucun fichier reçu dans la requête');
        return res.status(400).json({ 
          error: 'Aucun fichier n\'a été fourni',
          details: {
            receivedFiles: req.files,
            body: req.body,
            headers: req.headers
          }
        });
      }

      console.log('Fichier reçu:', {
        originalname: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size,
        path: req.file.path
      });

      const { description } = req.body;
      const fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
      const filePath = `/uploads/${req.file.filename}`;

      const [result] = await pool.query(
        `INSERT INTO publications 
        (user_id, uri, type, description) 
        VALUES (?, ?, ?, ?)`,
        [req.user.id, filePath, fileType, description]
      );

      // Envoyer une réponse plus détaillée
      res.status(201).json({
        success: true,
        message: 'Upload réussi',
        media: {
          id: result.insertId,
          path: filePath,
          type: fileType,
          description,
          url: `${req.protocol}://${req.get('host')}${filePath}`
        }
      });

    } catch (err) {
      console.error('Erreur lors de l\'enregistrement:', err);
      
      // Nettoyage du fichier en cas d'erreur
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }

      res.status(500).json({ 
        error: 'Échec de l\'enregistrement en base de données',
        details: err.message
      });
    }
  }
);

app.get('/api/publications', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [rows] = await pool.query(`
      SELECT 
        id,
        uri,
        description,
        type,
        created_at as createdAt
      FROM publications 
      WHERE user_id = ?
      ORDER BY created_at DESC
    `, [userId]);

    res.json(rows);
  } catch (err) {
    console.error('Erreur lors de la récupération des médias:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/media/:id', authenticateToken, async (req, res) => {
  const mediaId = req.params.id;
  const userId = req.user.id;

  try {
    const [media] = await pool.query(
      'SELECT uri FROM publications WHERE id = ? AND user_id = ?',
      [mediaId, userId]
    );

    if (media.length === 0) {
      return res.status(404).json({ error: 'Média non trouvé' });
    }

    // Supprimer le fichier physique
    const filePath = path.join(__dirname, 'uploads', media[0].uri);
    fs.unlink(filePath, (err) => {
      if (err) console.error('Erreur lors de la suppression du fichier:', err);
    });

    await pool.query('DELETE FROM publications WHERE id = ?', [mediaId]);

    res.json({ message: 'Média supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression du média:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// app.get('/api/publications', async (req, res) => {
//   const { userId } = req.query;

//   if (!userId) {
//     return res.status(400).json({ error: 'userId requis' });
//   }

//   try {
//     const query = `
//       SELECT 
//         p.id,
//         p.uri,
//         p.description,
//         p.type,
//         p.created_at as createdAt,
//         p.likes,
//         p.views,
//         u.username,
//         ai.profile_image as userProfileImage
//       FROM publications p
//       LEFT JOIN users u ON p.user_id = u.id
//       LEFT JOIN artisan_info ai ON p.user_id = ai.artisan_id
//       WHERE p.user_id = ?
//       ORDER BY p.created_at DESC
//     `;

//     const [rows] = await pool.query(query, [userId]);
//     res.json(rows);

//   } catch (err) {
//     console.error('❌ Erreur récupération publications utilisateur:', err);
//     res.status(500).json({ error: 'Erreur serveur' });
//   }
// });


app.post('/api/publications/:id/like', authenticateToken, async (req, res) => {
  const publicationId = req.params.id;
  const userId = req.user.id;

  try {
    const [existing] = await pool.query(
      'SELECT * FROM publication_likes WHERE publication_id = ? AND user_id = ?',
      [publicationId, userId]
    );

    if (existing.length > 0) {
      return res.status(400).json({ error: 'Vous avez déjà liké cette publication' });
    }

    await pool.query('INSERT INTO publication_likes (publication_id, user_id) VALUES (?, ?)', [publicationId, userId]);
    await pool.query('UPDATE publications SET likes = likes + 1 WHERE id = ?', [publicationId]);

    res.json({ message: 'Like ajouté avec succès' });
  } catch (err) {
    console.error('Erreur lors de l\'ajout du like:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/publications/:id/view', async (req, res) => {
  const publicationId = req.params.id;

  try {
    await pool.query('UPDATE publications SET views = views + 1 WHERE id = ?', [publicationId]);
    res.json({ message: 'Vue comptabilisée' });
  } catch (err) {
    console.error('Erreur lors de la comptabilisation de la vue:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});



// Récupérer uniquement les posts des artisans
app.get('/api/artisans/posts', authenticateToken, async (req, res) => {
  try {
    const [posts] = await pool.query(`
      SELECT 
        p.id,
        p.uri,
        p.type,
        p.description,
        p.likes,
        p.views,
        p.created_at as createdAt,
        u.id as userId,
        u.username,
        u.role,
        ai.profile_image as userProfileImage,
        aj.job as artisanJob,
        EXISTS(
          SELECT 1 FROM publication_likes pl 
          WHERE pl.publication_id = p.id AND pl.user_id = ?
        ) as isLiked
      FROM publications p
      JOIN users u ON p.user_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      LEFT JOIN artisan_jobs aj ON u.id = aj.artisan_id
      WHERE u.role = 'artisans'
      ORDER BY p.created_at DESC
    `, [req.user.id]);

    // Convertir les chemins en URLs absolues
    const formattedPosts = posts.map(post => ({
      ...post,
      uri: `${req.protocol}://${req.get('host')}${post.uri}`,
      userProfileImage: post.userProfileImage 
        ? `${req.protocol}://${req.get('host')}/uploads/${post.userProfileImage}`
        : null,
      isLiked: Boolean(post.isLiked),
      artisanJob: post.artisanJob || 'Artisan'
    }));

    res.json(formattedPosts);
  } catch (err) {
    console.error('Erreur récupération posts artisans:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * @route POST /api/posts/:id/toggle-like
 * @description Basculer l'état like/unlike d'une publication
 * @access Authentifié
 */
app.post('/api/posts/:id/toggle-like', authenticateToken, async (req, res) => {
  const { id: postId } = req.params;
  const { id: userId } = req.user;

  try {
    // Vérification de l'existence du post
    const [post] = await pool.query('SELECT id FROM publications WHERE id = ?', [postId]);
    if (!post.length) {
      return res.status(404).json({ success: false, error: 'Publication introuvable' });
    }

    // Transaction pour garantir l'intégrité des données
    const conn = await pool.getConnection();
    await conn.beginTransaction();

    try {
      // Vérification du statut actuel
      const [like] = await conn.query(
        'SELECT id FROM publication_likes WHERE publication_id = ? AND user_id = ?', 
        [postId, userId]
      );

      let action, likesCount;
      if (like.length > 0) {
        // Retirer le like
        await conn.query(
          'DELETE FROM publication_likes WHERE id = ?',
          [like[0].id]
        );
        await conn.query(
          'UPDATE publications SET likes = likes - 1 WHERE id = ?',
          [postId]
        );
        action = 'unliked';
      } else {
        // Ajouter le like
        await conn.query(
          'INSERT INTO publication_likes (publication_id, user_id) VALUES (?, ?)',
          [postId, userId]
        );
        await conn.query(
          'UPDATE publications SET likes = likes + 1 WHERE id = ?',
          [postId]
        );
        action = 'liked';
      }

      // Récupération du nouveau compte
      const [updated] = await conn.query(
        'SELECT likes FROM publications WHERE id = ?',
        [postId]
      );
      likesCount = updated[0].likes;

      await conn.commit();
      
      res.json({
        success: true,
        action,
        likes: likesCount,
        isLiked: action === 'liked'
      });

    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

  } catch (err) {
    console.error('Erreur toggle like:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la mise à jour du like'
    });
  }
});






// Routes pour les devis
app.post('/api/devis', authenticateToken, [
  body('title').notEmpty().withMessage('Le titre est requis'),
  body('description').notEmpty().withMessage('La description est requise'),
  body('type').isIn(['urgent', 'standard']).withMessage('Type de devis invalide')
], async (req, res) => {
  // Validation des champs
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

  // Récupération des données
  const { 
    title, 
    description, 
    address = null, 
    phone = null, 
    preferred_date = null, 
    budget = null, 
    type 
  } = req.body;

  const clientId = req.user.id;

  try {
    // Insertion dans la table devis
    const [result] = await pool.query(
      `INSERT INTO devis 
      (client_id, title, description, address, phone, preferred_date, budget, type) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [clientId, title, description, address, phone, preferred_date, budget, type]
    );

    // Récupération du devis nouvellement inséré
    const [devis] = await pool.query(`
      SELECT d.*, u.username AS client_name, u.phone AS client_phone 
      FROM devis d
      JOIN users u ON d.client_id = u.id
      WHERE d.id = ?
    `, [result.insertId]);

    res.status(201).json({
      success: true,
      message: 'Devis créé avec succès',
      devis: devis[0]
    });

  } catch (err) {
    console.error('Erreur création devis:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la création du devis' 
    });
  }
});
/**
 * @route GET /api/devis/client
 * @description Récupérer les devis d'un client
 * @access Authentifié (client)
 */
app.get('/api/devis/client', authenticateToken, async (req, res) => {
  try {
    const [devis] = await pool.query(`
      SELECT 
        d.*,
        COUNT(dr.id) as responses_count,
        u.username as client_name
      FROM devis d
      LEFT JOIN devis_responses dr ON d.id = dr.devis_id
      JOIN users u ON d.client_id = u.id
      WHERE d.client_id = ?
      GROUP BY d.id
      ORDER BY d.created_at DESC
    `, [req.user.id]);

    res.json({
      success: true,
      devis: devis.map(d => ({
        ...d,
        responses_count: parseInt(d.responses_count)
      }))
    });
  } catch (err) {
    console.error('Erreur récupération devis client:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la récupération des devis' 
    });
  }
});

/**
 * @route GET /api/devis/artisan
 * @description Récupérer les devis disponibles pour un artisan
 * @access Authentifié (artisan)
 */
app.get('/api/devis/artisan', authenticateToken, async (req, res) => {
  if (req.user.role !== 'artisans') {
    return res.status(403).json({ 
      success: false,
      error: 'Accès réservé aux artisans' 
    });
  }

  try {
    // Récupérer les devis où l'artisan n'a pas encore répondu
    const [devis] = await pool.query(`
      SELECT 
        d.*,
        u.username as client_name,
        (SELECT COUNT(*) FROM devis_responses dr WHERE dr.devis_id = d.id) as responses_count,
        (SELECT COUNT(*) FROM devis_responses dr WHERE dr.devis_id = d.id AND dr.artisan_id = ?) as has_responded
      FROM devis d
      JOIN users u ON d.client_id = u.id
      WHERE d.status = 'pending'
      HAVING has_responded = 0
      ORDER BY d.created_at DESC
    `, [req.user.id]);

    res.json({
      success: true,
      devis: devis.map(d => ({
        ...d,
        responses_count: parseInt(d.responses_count),
        has_responded: parseInt(d.has_responded) > 0
      }))
    });
  } catch (err) {
    console.error('Erreur récupération devis artisan:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la récupération des devis' 
    });
  }
});

/**
 * @route POST /api/devis/:id/respond
 * @description Répondre à un devis (artisan)
 * @access Authentifié (artisan)
 */
app.post('/api/devis/respond', authenticateToken, [
  body('price').notEmpty().withMessage('Le prix est requis'),
  body('estimated_time').notEmpty().withMessage('Le délai estimé est requis'),
  body('devisId').notEmpty().withMessage('L\'ID du devis est requis')
], async (req, res) => {
  if (req.user.role !== 'artisans') {
    return res.status(403).json({
      success: false,
      error: 'Accès réservé aux artisans'
    });
  }

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  // ✅ Prend l'ID du devis dans le body
  const { devisId, price, estimated_time, message } = req.body;

  try {
    // Vérifier si le devis existe et est en attente
    const [devis] = await pool.query(
      'SELECT id, status FROM devis WHERE id = ?',
      [devisId]
    );

    if (devis.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Devis non trouvé'
      });
    }

    if (devis[0].status !== 'pending') {
      return res.status(400).json({
        success: false,
        error: 'Ce devis n\'accepte plus de réponses'
      });
    }

    // Vérifier si l'artisan a déjà répondu
    const [existingResponse] = await pool.query(
      'SELECT id FROM devis_responses WHERE devis_id = ? AND artisan_id = ?',
      [devisId, req.user.id]
    );

    if (existingResponse.length > 0) {
      return res.status(400).json({
        success: false,
        error: 'Vous avez déjà répondu à ce devis'
      });
    }

    // Enregistrer la réponse
    const [result] = await pool.query(
      `INSERT INTO devis_responses 
      (devis_id, artisan_id, price, estimated_time, message) 
      VALUES (?, ?, ?, ?, ?)`,
      [devisId, req.user.id, price, estimated_time, message]
    );

    // Mettre à jour le statut du devis
    await pool.query(
      `UPDATE devis SET status = 'responded' 
      WHERE id = ? AND status = 'pending'`,
      [devisId]
    );

    // Récupérer les infos complètes de la réponse
    const [response] = await pool.query(`
      SELECT dr.*, u.username as artisan_name, ai.profile_image as artisan_avatar, aj.job as artisan_job
      FROM devis_responses dr
      JOIN users u ON dr.artisan_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      LEFT JOIN artisan_jobs aj ON u.id = aj.artisan_id
      WHERE dr.id = ?
    `, [result.insertId]);

    res.status(201).json({
      success: true,
      message: 'Réponse enregistrée avec succès',
      response: response[0]
    });

  } catch (err) {
    console.error('Erreur réponse devis:', err);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de l\'enregistrement de la réponse'
    });
  }
});

/**
 * @route GET /api/devis/:id/responses
 * @description Récupérer les réponses à un devis
 * @access Authentifié (client ou artisan concerné)
 */
app.get('/api/devis/:id/responses', authenticateToken, async (req, res) => {
  const devisId = req.params.id;

  try {
    // Vérifier les permissions
    const [devis] = await pool.query(
      'SELECT client_id FROM devis WHERE id = ?',
      [devisId]
    );

    if (devis.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Devis non trouvé' 
      });
    }

    const isClient = devis[0].client_id === req.user.id;
    const isArtisan = req.user.role === 'artisans';

    if (!isClient && !isArtisan) {
      return res.status(403).json({ 
        success: false,
        error: 'Accès non autorisé' 
      });
    }

    // Construire la requête en fonction du rôle
    let query = `
      SELECT 
        dr.*,
        u.username as artisan_name,
        u.phone as  artisan_phone,
        ai.profile_image as artisan_avatar,
        aj.job as artisan_job,
        (SELECT COUNT(*) FROM publication_likes pl JOIN publications p ON pl.publication_id = p.id WHERE p.user_id = u.id) as artisan_likes,
        (SELECT COUNT(*) FROM publications p WHERE p.user_id = u.id) as artisan_posts
      FROM devis_responses dr
      JOIN users u ON dr.artisan_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      LEFT JOIN artisan_jobs aj ON u.id = aj.artisan_id
      WHERE dr.devis_id = ?
    `;

    // Si c'est un artisan, ne retourner que ses propres réponses
    if (isArtisan && !isClient) {
      query += ' AND dr.artisan_id = ?';
      var params = [devisId, req.user.id];
    } else {
      var params = [devisId];
    }

    query += ' ORDER BY dr.created_at DESC';

    const [responses] = await pool.query(query, params);

    res.json({
      success: true,
      responses: responses.map(r => ({
        ...r,
        artisan_likes: parseInt(r.artisan_likes),
        artisan_posts: parseInt(r.artisan_posts)
      }))
    });

  } catch (err) {
    console.error('Erreur récupération réponses:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la récupération des réponses' 
    });
  }
});

/**
 * @route PUT /api/devis/responses/:id/status
 * @description Changer le statut d'une réponse (accepté/rejeté)
 * @access Authentifié (client)
 */
app.put('/api/devis/responses/:id/status', authenticateToken, [
  body('status').isIn(['accepted', 'rejected']).withMessage('Statut invalide')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const responseId = req.params.id;
  const { status } = req.body;

  try {
    // Vérifier que le client est bien le propriétaire du devis
    const [response] = await pool.query(`
      SELECT dr.id, d.client_id 
      FROM devis_responses dr
      JOIN devis d ON dr.devis_id = d.id
      WHERE dr.id = ?
    `, [responseId]);

    if (response.length === 0) {
      return res.status(404).json({ 
        success: false,
        error: 'Réponse non trouvée' 
      });
    }

    if (response[0].client_id !== req.user.id) {
      return res.status(403).json({ 
        success: false,
        error: 'Vous n\'êtes pas autorisé à modifier cette réponse' 
      });
    }

    // Mettre à jour le statut de la réponse
    await pool.query(
      'UPDATE devis_responses SET status = ? WHERE id = ?',
      [status, responseId]
    );

    // Si la réponse est acceptée, marquer le devis comme complété
    if (status === 'accepted') {
      await pool.query(
        'UPDATE devis SET status = ? WHERE id = (SELECT devis_id FROM devis_responses WHERE id = ?)',
        ['completed', responseId]
      );

      // Rejeter automatiquement toutes les autres réponses
      await pool.query(
        `UPDATE devis_responses SET status = 'rejected' 
        WHERE devis_id = (SELECT devis_id FROM devis_responses WHERE id = ?) 
        AND id != ?`,
        [responseId, responseId]
      );
    }

    res.json({
      success: true,
      message: 'Statut de la réponse mis à jour'
    });

  } catch (err) {
    console.error('Erreur mise à jour statut réponse:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la mise à jour du statut' 
    });
  }
});


/**
 * @route GET /api/devis/particulier
 * @description Récupérer les devis envoyés par un particulier
 * @access Authentifié (particulier seulement)
 */
app.get('/api/devis/particulier', authenticateToken, async (req, res) => {
  // Vérifier que l'utilisateur est bien un particulier
  if (req.user.role !== 'particuliers') {
    return res.status(403).json({ 
      success: false,
      error: 'Accès réservé aux particuliers' 
    });
  }

  try {
    // Récupérer les devis avec le nombre de réponses et les informations des artisans
    const [devis] = await pool.query(`
      SELECT 
        d.id,
        d.title,
        d.description,
        d.address,
        d.phone,
        d.preferred_date as preferredDate,
        d.budget,
        d.type,
        d.status,
        d.created_at as createdAt,
        COUNT(dr.id) as responsesCount,
        JSON_ARRAYAGG(
          JSON_OBJECT(
            'id', dr.id,
            'artisanId', dr.artisan_id,
            'artisanName', u.username,
            'artisanJob', aj.job,
            'artisanAvatar', ai.profile_image,
            'price', dr.price,
            'estimatedTime', dr.estimated_time,
            'message', dr.message,
            'status', dr.status,
            'createdAt', dr.created_at
          )
        ) as responses
      FROM devis d
      LEFT JOIN devis_responses dr ON d.id = dr.devis_id
      LEFT JOIN users u ON dr.artisan_id = u.id
      LEFT JOIN artisan_jobs aj ON u.id = aj.artisan_id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      WHERE d.client_id = ?
      GROUP BY d.id
      ORDER BY d.created_at DESC
    `, [req.user.id]);

    // Formater les données de retour
    const formattedDevis = devis.map(devisItem => ({
      ...devisItem,
      responsesCount: parseInt(devisItem.responsesCount),
      responses: devisItem.responses[0] ? JSON.parse(devisItem.responses) : []
    }));

    res.json({
      success: true,
      devis: formattedDevis
    });

  } catch (err) {
    console.error('Erreur récupération devis particulier:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la récupération des devis' 
    });
  }
});


/**
 * @route POST /api/calls/start
 * @description Démarrer un appel et notifier l'artisan via Socket.IO
 * @access Authentifié
 */
app.post('/api/calls/start', authenticateToken, [
  body('artisanId').notEmpty().withMessage('ID de l\'artisan requis')
], async (req, res) => {
  const { artisanId } = req.body;
  const callerId = req.user.id;

  try {
    // 1. Vérifier que l'artisan est connecté
    if (!onlineUsers.has(artisanId)) {
      return res.status(400).json({ 
        success: false,
        error: "L'artisan n'est pas connecté" 
      });
    }

    // 2. Créer une room Daily.co
    const roomName = `call-${callerId}-${artisanId}-${Date.now()}`;
    const response = await fetch('https://api.daily.co/v1/rooms', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${DAILY_API_KEY}`
      },
      body: JSON.stringify({
        name: roomName,
        privacy: 'private',
        properties: {
          enable_knocking: true,
          start_video_off: false,
          start_audio_off: false,
          enable_p2p: true
        }
      })
    });

    const roomData = await response.json();

    // 3. Enregistrer l'appel en BDD
    const [call] = await pool.query(
      `INSERT INTO calls 
      (caller_id, artisan_id, room_name, room_url, status) 
      VALUES (?, ?, ?, ?, ?)`,
      [callerId, artisanId, roomName, roomData.url, 'ringing']
    );

    // 4. Envoyer la notification via Socket.IO
    io.to(`user-${artisanId}`).emit('incoming-call', {
      callId: call.insertId,
      roomUrl: roomData.url,
      caller: {
        id: req.user.id,
        username: req.user.username,
      },
      timestamp: new Date()
    });

    // 5. Timeout si pas de réponse (30s)
    setTimeout(async () => {
      const [currentCall] = await pool.query(
        'SELECT status FROM calls WHERE id = ?',
        [call.insertId]
      );
      
      if (currentCall[0]?.status === 'ringing') {
        await pool.query(
          'UPDATE calls SET status = "missed" WHERE id = ?',
          [call.insertId]
        );
        io.to(`user-${artisanId}`).emit('call-missed', { callId: call.insertId });
        io.to(`user-${callerId}`).emit('call-not-answered', { callId: call.insertId });
      }
    }, 30000);

    res.json({ 
      success: true,
      callId: call.insertId,
      roomUrl: roomData.url
    });

  } catch (err) {
    console.error('Erreur démarrage appel:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors du démarrage de l\'appel' 
    });
  }
});

/**
 * @route POST /api/calls/:id/accept
 * @description Accepter un appel entrant
 * @access Authentifié
 */
app.post('/api/calls/:id/accept', authenticateToken, async (req, res) => {
  const callId = req.params.id;
  const artisanId = req.user.id;

  try {
    // 1. Vérifier que l'appel existe
    const [call] = await pool.query(
      `SELECT caller_id, room_url FROM calls 
      WHERE id = ? AND artisan_id = ? AND status = 'ringing'`,
      [callId, artisanId]
    );

    if (!call.length) {
      return res.status(404).json({ 
        success: false,
        error: 'Appel non trouvé ou déjà traité' 
      });
    }

    // 2. Mettre à jour le statut
    await pool.query(
      `UPDATE calls SET status = 'ongoing', started_at = NOW() 
      WHERE id = ?`,
      [callId]
    );

    // 3. Notifier l'appelant
    io.to(`user-${call[0].caller_id}`).emit('call-accepted', {
      callId,
      roomUrl: call[0].room_url
    });

    res.json({ 
      success: true,
      roomUrl: call[0].room_url 
    });

  } catch (err) {
    console.error('Erreur acceptation appel:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de l\'acceptation de l\'appel' 
    });
  }
});

/**
 * @route POST /api/calls/:id/reject
 * @description Rejeter un appel entrant
 * @access Authentifié
 */
app.post('/api/calls/:id/reject', authenticateToken, async (req, res) => {
  const callId = req.params.id;
  const artisanId = req.user.id;

  try {
    const [call] = await pool.query(
      `SELECT caller_id FROM calls 
      WHERE id = ? AND artisan_id = ? AND status = 'ringing'`,
      [callId, artisanId]
    );

    if (!call.length) {
      return res.status(404).json({ 
        success: false,
        error: 'Appel non trouvé ou déjà traité' 
      });
    }

    await pool.query(
      `UPDATE calls SET status = 'rejected', ended_at = NOW() 
      WHERE id = ?`,
      [callId]
    );

    io.to(`user-${call[0].caller_id}`).emit('call-rejected', { callId });

    res.json({ 
      success: true,
      message: 'Appel rejeté' 
    });

  } catch (err) {
    console.error('Erreur rejet appel:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors du rejet de l\'appel' 
    });
  }
});

/**
 * @route POST /api/calls/:id/end
 * @description Terminer un appel en cours
 * @access Authentifié
 */
app.post('/api/calls/:id/end', authenticateToken, async (req, res) => {
  const callId = req.params.id;
  const userId = req.user.id;

  try {
    // Vérifier que l'utilisateur fait partie de l'appel
    const [call] = await pool.query(
      `SELECT caller_id, artisan_id, room_name 
      FROM calls 
      WHERE id = ? AND (caller_id = ? OR artisan_id = ?) 
      AND status = 'ongoing'`,
      [callId, userId, userId]
    );

    if (!call.length) {
      return res.status(404).json({ 
        success: false,
        error: 'Appel non trouvé ou déjà terminé' 
      });
    }

    // Mettre à jour le statut de l'appel
    await pool.query(
      `UPDATE calls SET status = 'completed', ended_at = NOW() 
      WHERE id = ?`,
      [callId]
    );

    // Supprimer la room Daily.co (optionnel)
    await fetch(`https://api.daily.co/v1/rooms/${call[0].room_name}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${DAILY_API_KEY}`
      }
    });

    // Notifier l'autre participant
    const otherUserId = userId === call[0].caller_id 
      ? call[0].artisan_id 
      : call[0].caller_id;
    
    io.to(`user-${otherUserId}`).emit('call-ended', { callId });

    res.json({ 
      success: true,
      message: 'Appel terminé avec succès' 
    });

  } catch (err) {
    console.error('Erreur fin appel:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la fin de l\'appel' 
    });
  }
});

/**
 * @route GET /api/calls/history
 * @description Récupérer l'historique des appels
 * @access Authentifié
 */
app.get('/api/calls/history', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const [calls] = await pool.query(`
      SELECT 
        c.id,
        c.room_url,
        c.status,
        c.started_at,
        c.ended_at,
        c.created_at,
        u.id as other_user_id,
        u.username as other_user_name,
        u.role as other_user_role,
        ai.profile_image as other_user_avatar
      FROM calls c
      JOIN users u ON (
        (c.caller_id = ? AND u.id = c.artisan_id) OR 
        (c.artisan_id = ? AND u.id = c.caller_id)
      )
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      WHERE c.caller_id = ? OR c.artisan_id = ?
      ORDER BY c.created_at DESC
      LIMIT 50
    `, [userId, userId, userId, userId]);

    res.json({
      success: true,
      calls
    });
  } catch (err) {
    console.error('Erreur récupération historique:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la récupération de l\'historique' 
    });
  }
});





/**
 * @route POST /api/conversations
 * @description Créer ou récupérer une conversation existante
 * @access Authentifié
 */
app.post('/api/conversations', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  const currentUserId = req.user.id;
  if (!userId) return res.status(400).json({ error: 'ID requis' });
  if (userId === currentUserId) return res.status(400).json({ error: 'Impossible de discuter avec soi-même' });

  const [existing] = await pool.query(
    `SELECT id FROM conversations WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)`,
    [currentUserId, userId, userId, currentUserId]
  );

  if (existing.length > 0) return res.json({ conversationId: existing[0].id });

  const [result] = await pool.query(
    `INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)`,
    [currentUserId, userId]
  );

  res.status(201).json({ conversationId: result.insertId });
});


/**
 * @route GET /api/conversations
 * @description Récupérer toutes les conversations de l'utilisateur
 * @access Authentifié
 */
app.get('/api/conversations', authenticateToken, async (req, res) => {
  const userId = req.user.id;

  const [rows] = await pool.query(
    `SELECT 
      c.id,
      c.updated_at,
      CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END AS other_user_id,
      u.username AS other_user_name,
      ai.profile_image AS other_user_avatar,
      (
        SELECT m.content FROM messages m 
        WHERE m.conversation_id = c.id ORDER BY m.created_at DESC LIMIT 1
      ) AS last_message
    FROM conversations c
    JOIN users u ON (u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END)
    LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
    WHERE c.user1_id = ? OR c.user2_id = ?
    ORDER BY c.updated_at DESC`,
    [userId, userId, userId, userId]
  );

  res.json({ conversations: rows });
});


/**
 * @route POST /api/messages
 * @description Envoyer un message
 * @access Authentifié
 */
app.post('/api/messages', authenticateToken, async (req, res) => {
  const { conversationId, content } = req.body;
  const senderId = req.user.id;

  if (!conversationId || !content) {
    return res.status(400).json({ error: 'ID conversation et contenu requis' });
  }

  try {
    // Vérifier que l'utilisateur fait partie de la conversation
    const [conversation] = await pool.query(
      `SELECT id FROM conversations 
      WHERE (user1_id = ? OR user2_id = ?) AND id = ?`,
      [senderId, senderId, conversationId]
    );

    if (conversation.length === 0) {
      return res.status(403).json({ error: 'Non autorisé' });
    }

    // Envoyer le message
    const [result] = await pool.query(
      `INSERT INTO messages 
      (conversation_id, sender_id, content) 
      VALUES (?, ?, ?)`,
      [conversationId, senderId, content]
    );

    // Mettre à jour la date de mise à jour de la conversation
    await pool.query(
      `UPDATE conversations 
      SET updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?`,
      [conversationId]
    );

    // Récupérer le message complet avec les infos de l'expéditeur
    const [message] = await pool.query(
      `SELECT 
        m.*,
        u.username as sender_name,
        ai.profile_image as sender_avatar
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      WHERE m.id = ?`,
      [result.insertId]
    );

    // Notifier l'autre utilisateur via Socket.IO
    const [otherUser] = await pool.query(
      `SELECT 
        CASE 
          WHEN user1_id = ? THEN user2_id
          ELSE user1_id
        END AS other_user_id
      FROM conversations 
      WHERE id = ?`,
      [senderId, conversationId]
    );

    if (otherUser.length > 0 && onlineUsers.has(otherUser[0].other_user_id)) {
      io.to(`user-${otherUser[0].other_user_id}`).emit('new-message', {
        conversationId,
        message: message[0]
      });
    }

    res.status(201).json(message[0]);
  } catch (err) {
    console.error('Erreur envoi message:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * @route GET /api/messages/:conversationId
 * @description Récupérer les messages d'une conversation
 * @access Authentifié
 */
app.get('/api/messages/:conversationId', authenticateToken, async (req, res) => {
  const { conversationId } = req.params;
  const userId = req.user.id;

  try {
    // Vérifier que l'utilisateur fait partie de la conversation
    const [conversation] = await pool.query(
      `SELECT id FROM conversations 
      WHERE (user1_id = ? OR user2_id = ?) AND id = ?`,
      [userId, userId, conversationId]
    );

    if (conversation.length === 0) {
      return res.status(403).json({ error: 'Non autorisé' });
    }

    // Marquer les messages comme lus
    await pool.query(
      `UPDATE messages 
      SET is_read = TRUE 
      WHERE conversation_id = ? AND sender_id != ? AND is_read = FALSE`,
      [conversationId, userId]
    );

    // Récupérer les messages
    const [messages] = await pool.query(
      `SELECT 
        m.*,
        u.username as sender_name,
        ai.profile_image as sender_avatar
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC`,
      [conversationId]
    );

    res.json(messages);
  } catch (err) {
    console.error('Erreur récupération messages:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

/**
 * @route GET /api/conversations/:userId
 * @description Récupérer une conversation spécifique avec un utilisateur
 * @access Authentifié
 */
app.get('/api/conversations/user/:userId', authenticateToken, async (req, res) => {
  const otherUserId = req.params.userId;
  const currentUserId = req.user.id;

  if (otherUserId === currentUserId) {
    return res.status(400).json({ error: 'Impossible de récupérer une conversation avec soi-même' });
  }

  try {
    const [conversation] = await pool.query(
      `SELECT id FROM conversations 
      WHERE (user1_id = ? AND user2_id = ?) 
      OR (user1_id = ? AND user2_id = ?)`,
      [currentUserId, otherUserId, otherUserId, currentUserId]
    );

    if (conversation.length === 0) {
      return res.status(404).json({ error: 'Conversation non trouvée' });
    }

    res.json({ conversationId: conversation[0].id });
  } catch (err) {
    console.error('Erreur récupération conversation:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});
app.get('/api/messages/:conversationId', authenticateToken, async (req, res) => {
  const { conversationId } = req.params;
  const userId = req.user.id;

  const [valid] = await pool.query(
    `SELECT id FROM conversations WHERE (user1_id = ? OR user2_id = ?) AND id = ?`,
    [userId, userId, conversationId]
  );
  if (valid.length === 0) return res.status(403).json({ error: 'Non autorisé' });

  const [messages] = await pool.query(
    `SELECT m.*, u.username, ai.profile_image 
     FROM messages m 
     JOIN users u ON u.id = m.sender_id
     LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
     WHERE m.conversation_id = ?
     ORDER BY m.created_at ASC`,
    [conversationId]
  );

  res.json(messages);
});

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

// Gestion des erreurs globales
app.use((err, req, res, next) => {
  console.error('Erreur non gérée:', err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

server.listen(PORT, () => {
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`📁 Dossier uploads: ${path.join(__dirname, 'uploads')}`);
});