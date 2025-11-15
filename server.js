const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors({
  origin: ['http://localhost:3000', 'exp://localhost:19000'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('Supabase credentials are missing!');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'eco-map-secret-key-change-in-production';

// Auth middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Требуется авторизация' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Проверяем существование пользователя
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, role, status')
      .eq('id', decoded.userId)
      .single();

    if (error || !user) {
      return res.status(403).json({ error: 'Пользователь не найден' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Неверный токен' });
  }
};

// File upload setup
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Разрешены только изображения'), false);
    }
  }
});

// Utility functions
const formatUserResponse = (user) => ({
  id: user.id,
  email: user.email,
  name: user.name,
  joinDate: new Date(user.join_date).toLocaleDateString('ru-RU'),
  reportsCount: user.reports_count,
  level: user.level,
  points: user.points,
  avatar: user.avatar_url,
  role: user.role,
  preferences: user.preferences,
  achievements: user.achievements
});

const formatReportResponse = (report) => ({
  id: report.id,
  title: report.title,
  description: report.description,
  type: report.type,
  urgency: report.urgency,
  address: report.address,
  coordinate: {
    latitude: parseFloat(report.latitude),
    longitude: parseFloat(report.longitude)
  },
  image: report.image_url,
  status: report.status,
  date: new Date(report.created_at).toLocaleDateString('ru-RU'),
  time: new Date(report.created_at).toLocaleTimeString('ru-RU', { 
    hour: '2-digit', 
    minute: '2-digit' 
  }),
  userId: report.user_id,
  userName: report.users?.name || 'Пользователь',
  likesCount: report.likes_count || 0,
  commentsCount: report.comments_count || 0
});

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Eco Map API работает',
    timestamp: new Date().toISOString()
  });
});

// Регистрация пользователя
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
    }

    if (name.trim().length < 2) {
      return res.status(400).json({ error: 'Имя должно содержать минимум 2 символа' });
    }

    // Проверка email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Введите корректный email' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Проверка существующего пользователя
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', normalizedEmail)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хеширование пароля
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Создание пользователя
    const { data: user, error } = await supabase
      .from('users')
      .insert([{
        email: normalizedEmail,
        password_hash: passwordHash,
        name: name.trim(),
        reports_count: 0,
        level: 1,
        points: 0,
        role: 'user',
        preferences: {
          notifications: true,
          newsletter: true,
          darkMode: false
        },
        achievements: ['Новичок']
      }])
      .select()
      .single();

    if (error) throw error;

    // JWT токен
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      success: true,
      user: formatUserResponse(user),
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Ошибка при регистрации' });
  }
});

// Вход пользователя
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Поиск пользователя
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', normalizedEmail)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Проверка пароля
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // JWT токен
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      user: formatUserResponse(user),
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка при входе' });
  }
});

// Получение профиля
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    res.json(formatUserResponse(user));

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Ошибка при получении профиля' });
  }
});

// Создание отчета
app.post('/api/reports', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const {
      title,
      description,
      type,
      urgency,
      address,
      latitude,
      longitude
    } = req.body;

    // Валидация
    if (!title || !type || !urgency || !address || !latitude || !longitude) {
      return res.status(400).json({ error: 'Все обязательные поля должны быть заполнены' });
    }

    if (title.trim().length < 5) {
      return res.status(400).json({ error: 'Заголовок должен содержать минимум 5 символов' });
    }

    let imageUrl = null;

    // Загрузка изображения
    if (req.file) {
      try {
        const fileName = `reports/${req.user.id}/${Date.now()}-${Math.random().toString(36).substring(7)}.jpg`;
        
        const { data, error: uploadError } = await supabase.storage
          .from('eco-map-images')
          .upload(fileName, req.file.buffer, {
            contentType: 'image/jpeg',
            upsert: false
          });

        if (!uploadError) {
          const { data: { publicUrl } } = supabase.storage
            .from('eco-map-images')
            .getPublicUrl(fileName);
          imageUrl = publicUrl;
        }
      } catch (uploadError) {
        console.error('Image upload error:', uploadError);
      }
    }

    // Создание отчета
    const { data: report, error } = await supabase
      .from('reports')
      .insert([{
        user_id: req.user.id,
        title: title.trim(),
        description: description?.trim(),
        type,
        urgency,
        address: address.trim(),
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        image_url: imageUrl,
        status: 'active',
        likes_count: 0,
        comments_count: 0
      }])
      .select(`
        *,
        users:user_id (name)
      `)
      .single();

    if (error) throw error;

    // Обновление статистики пользователя
    await updateUserStats(req.user.id);

    res.status(201).json({
      success: true,
      report: formatReportResponse(report)
    });

  } catch (error) {
    console.error('Create report error:', error);
    res.status(500).json({ error: 'Ошибка при создании отчета' });
  }
});

// Получение всех отчетов
app.get('/api/reports', async (req, res) => {
  try {
    const { page = 1, limit = 50, type, status, userId } = req.query;
    const offset = (page - 1) * limit;

    let query = supabase
      .from('reports')
      .select(`
        *,
        users:user_id (name, avatar_url),
        report_likes!inner(count)
      `, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);

    // Фильтры
    if (type) query = query.eq('type', type);
    if (status) query = query.eq('status', status);
    if (userId) query = query.eq('user_id', userId);

    const { data: reports, error, count } = await query;

    if (error) throw error;

    const formattedReports = reports.map(report => formatReportResponse({
      ...report,
      likes_count: report.report_likes[0]?.count || 0
    }));

    res.json({
      success: true,
      reports: formattedReports,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: count,
        totalPages: Math.ceil(count / limit)
      }
    });

  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: 'Ошибка при получении отчетов' });
  }
});

// Получение отчетов текущего пользователя
app.get('/api/users/reports', authenticateToken, async (req, res) => {
  try {
    const { data: reports, error } = await supabase
      .from('reports')
      .select(`
        *,
        users:user_id (name),
        report_likes!inner(count)
      `)
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const formattedReports = reports.map(report => formatReportResponse({
      ...report,
      likes_count: report.report_likes[0]?.count || 0
    }));

    res.json({
      success: true,
      reports: formattedReports
    });

  } catch (error) {
    console.error('Get user reports error:', error);
    res.status(500).json({ error: 'Ошибка при получении отчетов' });
  }
});

// Лайк отчета
app.post('/api/reports/:id/like', authenticateToken, async (req, res) => {
  try {
    const reportId = req.params.id;

    // Проверка существования отчета
    const { data: report, error: reportError } = await supabase
      .from('reports')
      .select('id')
      .eq('id', reportId)
      .single();

    if (reportError || !report) {
      return res.status(404).json({ error: 'Отчет не найден' });
    }

    // Проверка существования лайка
    const { data: existingLike } = await supabase
      .from('report_likes')
      .select('id')
      .eq('user_id', req.user.id)
      .eq('report_id', reportId)
      .single();

    let result;
    if (existingLike) {
      // Удаление лайка
      result = await supabase
        .from('report_likes')
        .delete()
        .eq('id', existingLike.id);
    } else {
      // Добавление лайка
      result = await supabase
        .from('report_likes')
        .insert([{
          user_id: req.user.id,
          report_id: reportId
        }]);
    }

    if (result.error) throw result.error;

    // Получение обновленного количества лайков
    const { data: likes, error: likesError } = await supabase
      .from('report_likes')
      .select('id', { count: 'exact' })
      .eq('report_id', reportId);

    if (likesError) throw likesError;

    res.json({
      success: true,
      likesCount: likes.length,
      liked: !existingLike
    });

  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ error: 'Ошибка при обработке лайка' });
  }
});

// Вспомогательная функция для обновления статистики пользователя
async function updateUserStats(userId) {
  try {
    const { data: reports, error: reportsError } = await supabase
      .from('reports')
      .select('id', { count: 'exact' })
      .eq('user_id', userId);

    if (reportsError) throw reportsError;

    const reportsCount = reports.length;
    const points = reportsCount * 50;
    const level = Math.floor(points / 200) + 1;

    // Достижения
    const achievements = ['Новичок'];
    if (reportsCount >= 1) achievements.push('Первый отчет');
    if (reportsCount >= 5) achievements.push('Активный участник');
    if (reportsCount >= 10) achievements.push('Эко-герой');

    // Обновление пользователя
    const { error: updateError } = await supabase
      .from('users')
      .update({
        reports_count: reportsCount,
        points: points,
        level: level,
        achievements: achievements,
        updated_at: new Date().toISOString()
      })
      .eq('id', userId);

    if (updateError) throw updateError;

  } catch (error) {
    console.error('Update user stats error:', error);
  }
}

// Обработка ошибок
app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({ 
    error: 'Внутренняя ошибка сервера',
    ...(process.env.NODE_ENV === 'development' && { details: error.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Маршрут не найден' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`📊 Supabase URL: ${process.env.SUPABASE_URL ? 'Настроен' : 'Не настроен'}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
});
