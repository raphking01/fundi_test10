require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
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

// Configuration de la base de données SQLite
const dbPath = process.env.DB_PATH || './fundi.db';
const db = new Database(dbPath, { verbose: console.log });

// Initialisation de la base de données
try {
  db.pragma('journal_mode = WAL');
  
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT CHECK(role IN ('artisans', 'particuliers')) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TRIGGER IF NOT EXISTS update_users_timestamp 
    AFTER UPDATE ON users 
    BEGIN
      UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
    END;
    
    CREATE TABLE IF NOT EXISTS artisan_jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      artisan_id INTEGER NOT NULL,
      job TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (artisan_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS artisan_info (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      artisan_id INTEGER NOT NULL,
      profile_image TEXT,
      cover_image TEXT,
      bio_description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (artisan_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS publications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      uri TEXT NOT NULL,
      description TEXT,
      type TEXT CHECK(type IN ('image', 'video')) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      likes INTEGER DEFAULT 0,
      views INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS publication_likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      publication_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (publication_id) REFERENCES publications(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE (publication_id, user_id)
    );
    
    CREATE TABLE IF NOT EXISTS devis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      address TEXT,
      phone TEXT,
      preferred_date TEXT,
      budget TEXT,
      type TEXT CHECK(type IN ('urgent', 'standard')) DEFAULT 'standard',
      status TEXT CHECK(status IN ('pending', 'responded', 'completed')) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS devis_responses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      devis_id INTEGER NOT NULL,
      artisan_id INTEGER NOT NULL,
      price TEXT NOT NULL,
      estimated_time TEXT NOT NULL,
      message TEXT,
      status TEXT CHECK(status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (devis_id) REFERENCES devis(id) ON DELETE CASCADE,
      FOREIGN KEY (artisan_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE TABLE IF NOT EXISTS calls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caller_id INTEGER NOT NULL,
      artisan_id INTEGER NOT NULL,
      room_name TEXT NOT NULL,
      room_url TEXT NOT NULL,
      status TEXT CHECK(status IN ('ringing', 'ongoing', 'completed', 'missed', 'rejected')) NOT NULL,
      started_at DATETIME,
      ended_at DATETIME,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (caller_id) REFERENCES users(id),
      FOREIGN KEY (artisan_id) REFERENCES users(id)
    );
    
    CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user1_id INTEGER NOT NULL,
      user2_id INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE (user1_id, user2_id)
    );
    
    CREATE TRIGGER IF NOT EXISTS update_conversations_timestamp 
    AFTER UPDATE ON conversations 
    BEGIN
      UPDATE conversations SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
    END;
    
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
      FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  console.log('✅ Base de données SQLite initialisée avec succès');
} catch (err) {
  console.error('❌ Erreur lors de l\'initialisation de la base de données:', err);
  process.exit(1);
}

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
  socket.on('accept-call', ({ callId }) => {
    try {
      const call = db.prepare(
        'SELECT caller_id, room_url FROM calls WHERE id = ?'
      ).get(callId);
      
      if (call) {
        io.to(`user-${call.caller_id}`).emit('call-accepted', {
          callId,
          roomUrl: call.room_url
        });
      }
    } catch (err) {
      console.error('Erreur accept-call:', err);
    }
  });

  socket.on('reject-call', ({ callId }) => {
    try {
      const call = db.prepare(
        'SELECT caller_id FROM calls WHERE id = ?'
      ).get(callId);
      
      if (call) {
        db.prepare(
          `UPDATE calls SET status = 'rejected', ended_at = datetime('now') 
          WHERE id = ?`
        ).run(callId);
        io.to(`user-${call.caller_id}`).emit('call-rejected', { callId });
      }
    } catch (err) {
      console.error('Erreur reject-call:', err);
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

app.post('/api/login', [
  body('phone').notEmpty().withMessage('Le numéro de téléphone est requis'),
  body('password').notEmpty().withMessage('Le mot de passe est requis')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { phone, password } = req.body;
  
  try {
    const user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Mot de passe incorrect' });
    }

    const job = db.prepare('SELECT job FROM artisan_jobs WHERE artisan_id = ?').get(user.id);
    const info = db.prepare('SELECT * FROM artisan_info WHERE artisan_id = ?').get(user.id);

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
      job: job?.job,
      profileImage: info?.profile_image,
      coverImage: info?.cover_image,
      bio: info?.bio_description
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
  (req, res) => {
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
      const existing = db.prepare(
        'SELECT id FROM users WHERE phone = ?'
      ).get(phone);
      
      if (existing) {
        return res.status(409).json({ 
          success: false,
          message: 'Ce numéro de téléphone est déjà utilisé' 
        });
      }

      // Hashage du mot de passe
      const hashedPassword = bcrypt.hashSync(password, 10);

      // Insertion de l'utilisateur
      const result = db.prepare(
        'INSERT INTO users (username, phone, password, role) VALUES (?, ?, ?, ?)'
      ).run(username, phone, hashedPassword, role);

      // Création du token JWT
      const token = jwt.sign(
        { 
          id: result.lastInsertRowid, 
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
          id: result.lastInsertRowid,
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

app.post(
  '/api/artisan/job',
  authenticateToken,
  [
    body('job')
      .notEmpty().trim().withMessage('Le métier est requis')
      .isLength({ max: 100 }).withMessage('Le métier ne doit pas dépasser 100 caractères')
  ],
  (req, res) => {
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
      const existingJob = db.prepare(
        'SELECT id FROM artisan_jobs WHERE artisan_id = ?'
      ).get(artisanId);

      if (existingJob) {
        // Mise à jour du métier existant
        db.prepare(
          'UPDATE artisan_jobs SET job = ? WHERE artisan_id = ?'
        ).run(job, artisanId);
      } else {
        // Insertion d'un nouveau métier
        db.prepare(
          'INSERT INTO artisan_jobs (artisan_id, job) VALUES (?, ?)'
        ).run(artisanId, job);
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
  (req, res) => {
    const { bio_description } = req.body;
    const userId = req.user.id;
    const profileImage = req.files['profile_image']?.[0]?.filename;
    const coverImage = req.files['cover_image']?.[0]?.filename;

    try {
      const existingInfo = db.prepare(
        'SELECT * FROM artisan_info WHERE artisan_id = ?'
      ).get(userId);
      
      if (existingInfo) {
        db.prepare(
          `UPDATE artisan_info 
          SET 
            profile_image = COALESCE(?, profile_image),
            cover_image = COALESCE(?, cover_image),
            bio_description = ?
          WHERE artisan_id = ?`
        ).run(profileImage, coverImage, bio_description, userId);
      } else {
        db.prepare(
          'INSERT INTO artisan_info (artisan_id, profile_image, cover_image, bio_description) VALUES (?, ?, ?, ?)'
        ).run(userId, profileImage, coverImage, bio_description);
      }

      const updatedInfo = db.prepare(`
        SELECT * FROM artisan_info 
        WHERE artisan_id = ?
      `).get(userId);
      
      res.json({ 
        message: 'Informations mises à jour',
        info: updatedInfo
      });
    } catch (err) {
      console.error('Erreur lors de la mise à jour des informations:', err);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

app.get('/api/artisan/info/:id', (req, res) => {
  const artisanId = req.params.id;
  
  try {
    const row = db.prepare(`
      SELECT ai.*, u.username, aj.job 
      FROM artisan_info ai
      LEFT JOIN users u ON ai.artisan_id = u.id
      LEFT JOIN artisan_jobs aj ON ai.artisan_id = aj.artisan_id
      WHERE ai.artisan_id = ?
    `).get(artisanId);

    if (!row) {
      return res.status(404).json({ error: 'Artisan non trouvé' });
    }

    res.json(row);
  } catch (err) {
    console.error('Erreur lors de la récupération des informations:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/uploadMedia', 
  authenticateToken,
  (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        console.error('Erreur Multer:', err);
        return res.status(400).json({ 
          error: err.code === 'LIMIT_FILE_SIZE' 
            ? 'Le fichier dépasse la taille maximale de 10MB' 
            : 'Erreur lors du téléchargement du fichier'
        });
      } else if (err) {
        console.error('Erreur inconnue:', err);
        return res.status(500).json({ error: 'Erreur serveur' });
      }
      next();
    });
  },
  (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ 
          error: 'Aucun fichier n\'a été fourni'
        });
      }

      const { description } = req.body;
      const fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
      const filePath = `/uploads/${req.file.filename}`;

      const result = db.prepare(
        `INSERT INTO publications 
        (user_id, uri, type, description) 
        VALUES (?, ?, ?, ?)`
      ).run(req.user.id, filePath, fileType, description);

      res.status(201).json({
        success: true,
        message: 'Upload réussi',
        media: {
          id: result.lastInsertRowid,
          path: filePath,
          type: fileType,
          description,
          url: `${req.protocol}://${req.get('host')}${filePath}`
        }
      });
    } catch (err) {
      console.error('Erreur lors de l\'enregistrement:', err);
      
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

app.get('/api/publications', authenticateToken, (req, res) => {
  const userId = req.user.id;

  try {
    const rows = db.prepare(`
      SELECT 
        id,
        uri,
        description,
        type,
        created_at as createdAt
      FROM publications 
      WHERE user_id = ?
      ORDER BY created_at DESC
    `).all(userId);

    res.json(rows);
  } catch (err) {
    console.error('Erreur lors de la récupération des médias:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/media/:id', authenticateToken, (req, res) => {
  const mediaId = req.params.id;
  const userId = req.user.id;

  try {
    const media = db.prepare(
      'SELECT uri FROM publications WHERE id = ? AND user_id = ?'
    ).get(mediaId, userId);

    if (!media) {
      return res.status(404).json({ error: 'Média non trouvé' });
    }

    const filePath = path.join(__dirname, 'uploads', path.basename(media.uri));
    fs.unlink(filePath, (err) => {
      if (err) console.error('Erreur lors de la suppression du fichier:', err);
    });

    db.prepare('DELETE FROM publications WHERE id = ?').run(mediaId);

    res.json({ message: 'Média supprimé avec succès' });
  } catch (err) {
    console.error('Erreur lors de la suppression du média:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/publications/:id/like', authenticateToken, (req, res) => {
  const publicationId = req.params.id;
  const userId = req.user.id;

  try {
    const existing = db.prepare(
      'SELECT * FROM publication_likes WHERE publication_id = ? AND user_id = ?'
    ).get(publicationId, userId);

    if (existing) {
      return res.status(400).json({ error: 'Vous avez déjà liké cette publication' });
    }

    db.transaction(() => {
      db.prepare(
        'INSERT INTO publication_likes (publication_id, user_id) VALUES (?, ?)'
      ).run(publicationId, userId);
      
      db.prepare(
        'UPDATE publications SET likes = likes + 1 WHERE id = ?'
      ).run(publicationId);
    })();

    res.json({ message: 'Like ajouté avec succès' });
  } catch (err) {
    console.error('Erreur lors de l\'ajout du like:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/publications/:id/view', (req, res) => {
  const publicationId = req.params.id;

  try {
    db.prepare(
      'UPDATE publications SET views = views + 1 WHERE id = ?'
    ).run(publicationId);
    
    res.json({ message: 'Vue comptabilisée' });
  } catch (err) {
    console.error('Erreur lors de la comptabilisation de la vue:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/artisans/posts', authenticateToken, (req, res) => {
  try {
    const posts = db.prepare(`
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
    `).all(req.user.id);

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

app.post('/api/posts/:id/toggle-like', authenticateToken, (req, res) => {
  const { id: postId } = req.params;
  const { id: userId } = req.user;

  try {
    const post = db.prepare(
      'SELECT id FROM publications WHERE id = ?'
    ).get(postId);
    
    if (!post) {
      return res.status(404).json({ success: false, error: 'Publication introuvable' });
    }

    let action, likesCount;
    
    db.transaction(() => {
      const like = db.prepare(
        'SELECT id FROM publication_likes WHERE publication_id = ? AND user_id = ?'
      ).get(postId, userId);

      if (like) {
        // Retirer le like
        db.prepare(
          'DELETE FROM publication_likes WHERE id = ?'
        ).run(like.id);
        
        db.prepare(
          'UPDATE publications SET likes = likes - 1 WHERE id = ?'
        ).run(postId);
        
        action = 'unliked';
      } else {
        // Ajouter le like
        db.prepare(
          'INSERT INTO publication_likes (publication_id, user_id) VALUES (?, ?)'
        ).run(postId, userId);
        
        db.prepare(
          'UPDATE publications SET likes = likes + 1 WHERE id = ?'
        ).run(postId);
        
        action = 'liked';
      }

      const updated = db.prepare(
        'SELECT likes FROM publications WHERE id = ?'
      ).get(postId);
      
      likesCount = updated.likes;
    })();
    
    res.json({
      success: true,
      action,
      likes: likesCount,
      isLiked: action === 'liked'
    });

  } catch (err) {
    console.error('Erreur toggle like:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la mise à jour du like'
    });
  }
});

app.post('/api/devis', authenticateToken, [
  body('title').notEmpty().withMessage('Le titre est requis'),
  body('description').notEmpty().withMessage('La description est requise'),
  body('type').isIn(['urgent', 'standard']).withMessage('Type de devis invalide')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      success: false,
      errors: errors.array() 
    });
  }

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
    const result = db.prepare(
      `INSERT INTO devis 
      (client_id, title, description, address, phone, preferred_date, budget, type) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(clientId, title, description, address, phone, preferred_date, budget, type);

    const devis = db.prepare(`
      SELECT d.*, u.username AS client_name, u.phone AS client_phone 
      FROM devis d
      JOIN users u ON d.client_id = u.id
      WHERE d.id = ?
    `).get(result.lastInsertRowid);

    res.status(201).json({
      success: true,
      message: 'Devis créé avec succès',
      devis
    });
  } catch (err) {
    console.error('Erreur création devis:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de la création du devis' 
    });
  }
});

app.get('/api/devis/client', authenticateToken, (req, res) => {
  try {
    const devis = db.prepare(`
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
    `).all(req.user.id);

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

app.get('/api/devis/artisan', authenticateToken, (req, res) => {
  if (req.user.role !== 'artisans') {
    return res.status(403).json({ 
      success: false,
      error: 'Accès réservé aux artisans' 
    });
  }

  try {
    // Correction de la requête SQL
    const devis = db.prepare(`
      SELECT 
        d.*,
        u.username as client_name,
        (SELECT COUNT(*) FROM devis_responses dr WHERE dr.devis_id = d.id) as responses_count,
        (SELECT COUNT(*) FROM devis_responses dr WHERE dr.devis_id = d.id AND dr.artisan_id = ?) as has_responded
      FROM devis d
      JOIN users u ON d.client_id = u.id
      WHERE d.status = 'pending'
      AND (SELECT COUNT(*) FROM devis_responses dr WHERE dr.devis_id = d.id AND dr.artisan_id = ?) = 0
      ORDER BY d.created_at DESC
    `).all(req.user.id, req.user.id);

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

app.post('/api/devis/respond', authenticateToken, [
  body('price').notEmpty().withMessage('Le prix est requis'),
  body('estimated_time').notEmpty().withMessage('Le délai estimé est requis'),
  body('devisId').notEmpty().withMessage('L\'ID du devis est requis')
], (req, res) => {
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

  const { devisId, price, estimated_time, message } = req.body;

  try {
    const devis = db.prepare(
      'SELECT id, status FROM devis WHERE id = ?'
    ).get(devisId);

    if (!devis) {
      return res.status(404).json({
        success: false,
        error: 'Devis non trouvé'
      });
    }

    if (devis.status !== 'pending') {
      return res.status(400).json({
        success: false,
        error: 'Ce devis n\'accepte plus de réponses'
      });
    }

    const existingResponse = db.prepare(
      'SELECT id FROM devis_responses WHERE devis_id = ? AND artisan_id = ?'
    ).get(devisId, req.user.id);

    if (existingResponse) {
      return res.status(400).json({
        success: false,
        error: 'Vous avez déjà répondu à ce devis'
      });
    }

    db.transaction(() => {
      const result = db.prepare(
        `INSERT INTO devis_responses 
        (devis_id, artisan_id, price, estimated_time, message) 
        VALUES (?, ?, ?, ?, ?)`
      ).run(devisId, req.user.id, price, estimated_time, message);

      db.prepare(
        `UPDATE devis SET status = 'responded' 
        WHERE id = ? AND status = 'pending'`
      ).run(devisId);

      const response = db.prepare(`
        SELECT dr.*, u.username as artisan_name, ai.profile_image as artisan_avatar, aj.job as artisan_job
        FROM devis_responses dr
        JOIN users u ON dr.artisan_id = u.id
        LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
        LEFT JOIN artisan_jobs aj ON u.id = aj.artisan_id
        WHERE dr.id = ?
      `).get(result.lastInsertRowid);

      res.status(201).json({
        success: true,
        message: 'Réponse enregistrée avec succès',
        response
      });
    });
  } catch (err) {
    console.error('Erreur réponse devis:', err);
    res.status(500).json({
      success: false,
      error: 'Erreur lors de l\'enregistrement de la réponse'
    });
  }
});

app.get('/api/devis/:id/responses', authenticateToken, (req, res) => {
  const devisId = req.params.id;

  try {
    const devis = db.prepare(
      'SELECT client_id FROM devis WHERE id = ?'
    ).get(devisId);

    if (!devis) {
      return res.status(404).json({ 
        success: false,
        error: 'Devis non trouvé' 
      });
    }

    const isClient = devis.client_id === req.user.id;
    const isArtisan = req.user.role === 'artisans';

    if (!isClient && !isArtisan) {
      return res.status(403).json({ 
        success: false,
        error: 'Accès non autorisé' 
      });
    }

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

    let params = [devisId];

    if (isArtisan && !isClient) {
      query += ' AND dr.artisan_id = ?';
      params.push(req.user.id);
    }

    query += ' ORDER BY dr.created_at DESC';

    const responses = db.prepare(query).all(...params);

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

app.put('/api/devis/responses/:id/status', authenticateToken, [
  body('status').isIn(['accepted', 'rejected']).withMessage('Statut invalide')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const responseId = req.params.id;
  const { status } = req.body;

  try {
    const response = db.prepare(`
      SELECT dr.id, d.client_id 
      FROM devis_responses dr
      JOIN devis d ON dr.devis_id = d.id
      WHERE dr.id = ?
    `).get(responseId);

    if (!response) {
      return res.status(404).json({ 
        success: false,
        error: 'Réponse non trouvée' 
      });
    }

    if (response.client_id !== req.user.id) {
      return res.status(403).json({ 
        success: false,
        error: 'Vous n\'êtes pas autorisé à modifier cette réponse' 
      });
    }

    db.transaction(() => {
      db.prepare(
        'UPDATE devis_responses SET status = ? WHERE id = ?'
      ).run(status, responseId);

      if (status === 'accepted') {
        db.prepare(
          'UPDATE devis SET status = ? WHERE id = ?'
        ).run('completed', response.devis_id);

        db.prepare(
          `UPDATE devis_responses SET status = 'rejected' 
          WHERE devis_id = ? AND id != ?`
        ).run(response.devis_id, responseId);
      }
    });

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

app.get('/api/devis/particulier', authenticateToken, (req, res) => {
  if (req.user.role !== 'particuliers') {
    return res.status(403).json({ 
      success: false,
      error: 'Accès réservé aux particuliers' 
    });
  }

  try {
    const devis = db.prepare(`
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
        (
          SELECT json_group_array(
            json_object(
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
          )
          FROM devis_responses dr
          LEFT JOIN users u ON dr.artisan_id = u.id
          LEFT JOIN artisan_jobs aj ON u.id = aj.artisan_id
          LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
          WHERE dr.devis_id = d.id
        ) as responses
      FROM devis d
      WHERE d.client_id = ?
      GROUP BY d.id
      ORDER BY d.created_at DESC
    `).all(req.user.id);

    const formattedDevis = devis.map(devisItem => ({
      ...devisItem,
      responsesCount: parseInt(devisItem.responsesCount),
      responses: devisItem.responses ? JSON.parse(devisItem.responses) : []
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

app.post('/api/calls/start', authenticateToken, [
  body('artisanId').notEmpty().withMessage('ID de l\'artisan requis')
], async (req, res) => {
  const { artisanId } = req.body;
  const callerId = req.user.id;

  try {
    if (!onlineUsers.has(artisanId)) {
      return res.status(400).json({ 
        success: false,
        error: "L'artisan n'est pas connecté" 
      });
    }

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

    const result = db.prepare(
      `INSERT INTO calls 
      (caller_id, artisan_id, room_name, room_url, status) 
      VALUES (?, ?, ?, ?, ?)`
    ).run(callerId, artisanId, roomName, roomData.url, 'ringing');

    io.to(`user-${artisanId}`).emit('incoming-call', {
      callId: result.lastInsertRowid,
      roomUrl: roomData.url,
      caller: {
        id: req.user.id,
        username: req.user.username,
      },
      timestamp: new Date()
    });

    setTimeout(() => {
      const currentCall = db.prepare(
        'SELECT status FROM calls WHERE id = ?'
      ).get(result.lastInsertRowid);
      
      if (currentCall?.status === 'ringing') {
        db.prepare(
          'UPDATE calls SET status = "missed", ended_at = datetime("now") WHERE id = ?'
        ).run(result.lastInsertRowid);
        
        io.to(`user-${artisanId}`).emit('call-missed', { callId: result.lastInsertRowid });
        io.to(`user-${callerId}`).emit('call-not-answered', { callId: result.lastInsertRowid });
      }
    }, 30000);

    res.json({ 
      success: true,
      callId: result.lastInsertRowid,
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

app.post('/api/calls/:id/accept', authenticateToken, (req, res) => {
  const callId = req.params.id;
  const artisanId = req.user.id;

  try {
    const call = db.prepare(
      `SELECT caller_id, room_url FROM calls 
      WHERE id = ? AND artisan_id = ? AND status = 'ringing'`
    ).get(callId, artisanId);

    if (!call) {
      return res.status(404).json({ 
        success: false,
        error: 'Appel non trouvé ou déjà traité' 
      });
    }

    db.prepare(
      `UPDATE calls SET status = 'ongoing', started_at = datetime('now') 
      WHERE id = ?`
    ).run(callId);

    io.to(`user-${call.caller_id}`).emit('call-accepted', {
      callId,
      roomUrl: call.room_url
    });

    res.json({ 
      success: true,
      roomUrl: call.room_url 
    });
  } catch (err) {
    console.error('Erreur acceptation appel:', err);
    res.status(500).json({ 
      success: false,
      error: 'Erreur lors de l\'acceptation de l\'appel' 
    });
  }
});

app.post('/api/calls/:id/reject', authenticateToken, (req, res) => {
  const callId = req.params.id;
  const artisanId = req.user.id;

  try {
    const call = db.prepare(
      `SELECT caller_id FROM calls 
      WHERE id = ? AND artisan_id = ? AND status = 'ringing'`
    ).get(callId, artisanId);

    if (!call) {
      return res.status(404).json({ 
        success: false,
        error: 'Appel non trouvé ou déjà traité' 
      });
    }

    db.prepare(
      `UPDATE calls SET status = 'rejected', ended_at = datetime('now') 
      WHERE id = ?`
    ).run(callId);

    io.to(`user-${call.caller_id}`).emit('call-rejected', { callId });

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

app.post('/api/calls/:id/end', authenticateToken, (req, res) => {
  const callId = req.params.id;
  const userId = req.user.id;

  try {
    const call = db.prepare(
      `SELECT caller_id, artisan_id, room_name 
      FROM calls 
      WHERE id = ? AND (caller_id = ? OR artisan_id = ?) 
      AND status = 'ongoing'`
    ).get(callId, userId, userId);

    if (!call) {
      return res.status(404).json({ 
        success: false,
        error: 'Appel non trouvé ou déjà terminé' 
      });
    }

    db.prepare(
      `UPDATE calls SET status = 'completed', ended_at = datetime('now') 
      WHERE id = ?`
    ).run(callId);

    // Supprimer la room Daily.co (optionnel)
    fetch(`https://api.daily.co/v1/rooms/${call.room_name}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${DAILY_API_KEY}`
      }
    }).catch(err => console.error('Erreur suppression room:', err));

    const otherUserId = userId === call.caller_id 
      ? call.artisan_id 
      : call.caller_id;
    
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

app.get('/api/calls/history', authenticateToken, (req, res) => {
  const userId = req.user.id;

  try {
    const calls = db.prepare(`
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
    `).all(userId, userId, userId, userId);

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

app.post('/api/conversations', authenticateToken, (req, res) => {
  const { userId } = req.body;
  const currentUserId = req.user.id;
  
  if (!userId) return res.status(400).json({ error: 'ID requis' });
  if (userId === currentUserId) return res.status(400).json({ error: 'Impossible de discuter avec soi-même' });

  try {
    const existing = db.prepare(
      `SELECT id FROM conversations WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)`
    ).get(currentUserId, userId, userId, currentUserId);

    if (existing) return res.json({ conversationId: existing.id });

    const result = db.prepare(
      `INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)`
    ).run(currentUserId, userId);

    res.status(201).json({ conversationId: result.lastInsertRowid });
  } catch (err) {
    console.error('Erreur création conversation:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/conversations', authenticateToken, (req, res) => {
  const userId = req.user.id;

  try {
    const rows = db.prepare(
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
      ORDER BY c.updated_at DESC`
    ).all(userId, userId, userId, userId);

    res.json({ conversations: rows });
  } catch (err) {
    console.error('Erreur récupération conversations:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/messages', authenticateToken, (req, res) => {
  const { conversationId, content } = req.body;
  const senderId = req.user.id;

  if (!conversationId || !content) {
    return res.status(400).json({ error: 'ID conversation et contenu requis' });
  }

  try {
    const conversation = db.prepare(
      `SELECT id FROM conversations 
      WHERE (user1_id = ? OR user2_id = ?) AND id = ?`
    ).get(senderId, senderId, conversationId);

    if (!conversation) {
      return res.status(403).json({ error: 'Non autorisé' });
    }

    const result = db.prepare(
      `INSERT INTO messages 
      (conversation_id, sender_id, content) 
      VALUES (?, ?, ?)`
    ).run(conversationId, senderId, content);

    db.prepare(
      `UPDATE conversations 
      SET updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?`
    ).run(conversationId);

    const message = db.prepare(
      `SELECT 
        m.*,
        u.username as sender_name,
        ai.profile_image as sender_avatar
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      WHERE m.id = ?`
    ).get(result.lastInsertRowid);

    const otherUser = db.prepare(
      `SELECT 
        CASE 
          WHEN user1_id = ? THEN user2_id
          ELSE user1_id
        END AS other_user_id
      FROM conversations 
      WHERE id = ?`
    ).get(senderId, conversationId);

    if (otherUser && onlineUsers.has(otherUser.other_user_id)) {
      io.to(`user-${otherUser.other_user_id}`).emit('new-message', {
        conversationId,
        message
      });
    }

    res.status(201).json(message);
  } catch (err) {
    console.error('Erreur envoi message:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/messages/:conversationId', authenticateToken, (req, res) => {
  const { conversationId } = req.params;
  const userId = req.user.id;

  try {
    const conversation = db.prepare(
      `SELECT id FROM conversations 
      WHERE (user1_id = ? OR user2_id = ?) AND id = ?`
    ).get(userId, userId, conversationId);

    if (!conversation) {
      return res.status(403).json({ error: 'Non autorisé' });
    }

    db.prepare(
      `UPDATE messages 
      SET is_read = 1 
      WHERE conversation_id = ? AND sender_id != ? AND is_read = 0`
    ).run(conversationId, userId);

    const messages = db.prepare(
      `SELECT 
        m.*,
        u.username as sender_name,
        ai.profile_image as sender_avatar
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      LEFT JOIN artisan_info ai ON u.id = ai.artisan_id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC`
    ).all(conversationId);

    res.json(messages);
  } catch (err) {
    console.error('Erreur récupération messages:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/conversations/user/:userId', authenticateToken, (req, res) => {
  const otherUserId = req.params.userId;
  const currentUserId = req.user.id;

  if (otherUserId === currentUserId) {
    return res.status(400).json({ error: 'Impossible de discuter avec soi-même' });
  }

  try {
    const conversation = db.prepare(
      `SELECT id FROM conversations 
      WHERE (user1_id = ? AND user2_id = ?) 
      OR (user1_id = ? AND user2_id = ?)`
    ).get(currentUserId, otherUserId, otherUserId, currentUserId);

    if (!conversation) {
      return res.status(404).json({ error: 'Conversation non trouvée' });
    }

    res.json({ conversationId: conversation.id });
  } catch (err) {
    console.error('Erreur récupération conversation:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
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
  console.log(`🗄️ Base de données SQLite: ${dbPath}`);
});
