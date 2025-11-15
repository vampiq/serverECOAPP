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
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'eco-map-secret-key';

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Требуется авторизация' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Неверный токен' });
    }
    req.user = user;
    next();
  });
};

// File upload setup (для загрузки изображений)
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Разрешены только изображения'), false);
    }
  }
});

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Eco Map API работает' });
});

// Регистрация пользователя
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Валидация
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен содержать минимум 6 символов' });
    }

    // Проверка существующего пользователя
    const { data: existingUser, error: checkError } = await supabase
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase())
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
      .insert([
        {
          email: email.toLowerCase(),
          password_hash: passwordHash,
          name: name.trim(),
          reports_count: 0,
          level: 1,
          points: 0,
          role: 'user'
        }
      ])
      .select()
      .single();

    if (error) throw error;

    // Создание JWT токена
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
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        joinDate: user.join_date,
        reportsCount: user.reports_count,
        level: user.level,
        points: user.points,
        role: user.role,
        preferences: user.preferences,
        achievements: user.achievements
      },
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

    // Поиск пользователя
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Проверка пароля
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Неверный email или пароль' });
    }

    // Создание JWT токена
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
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        joinDate: user.join_date,
        reportsCount: user.reports_count,
        level: user.level,
        points: user.points,
        role: user.role,
        preferences: user.preferences,
        achievements: user.achievements
      },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка при входе' });
  }
});

// Получение профиля пользователя
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.userId)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      joinDate: user.join_date,
      reportsCount: user.reports_count,
      level: user.level,
      points: user.points,
      role: user.role,
      preferences: user.preferences,
      achievements: user.achievements
    });

  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Ошибка при получении профиля' });
  }
});

// Создание отчета о загрязнении
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

    let imageUrl = null;

    // Загрузка изображения в Supabase Storage (если есть)
    if (req.file) {
      const fileName = `reports/${req.user.userId}/${Date.now()}-${req.file.originalname}`;
      const { data: uploadData, error: uploadError } = await supabase.storage
        .from('eco-map-images')
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype
        });

      if (!uploadError) {
        const { data: publicUrlData } = supabase.storage
          .from('eco-map-images')
          .getPublicUrl(fileName);
        imageUrl = publicUrlData.publicUrl;
      }
    }

    // Создание отчета
    const { data: report, error } = await supabase
      .from('reports')
      .insert([
        {
          user_id: req.user.userId,
          title,
          description,
          type,
          urgency,
          address,
          latitude: parseFloat(latitude),
          longitude: parseFloat(longitude),
          image_url: imageUrl,
          status: 'active'
        }
      ])
      .select(`
        *,
        users:user_id (name, email)
      `)
      .single();

    if (error) throw error;

    // Обновление статистики пользователя
    await updateUserStats(req.user.userId);

    res.status(201).json({
      success: true,
      report: {
        id: report.id,
        title: report.title,
        description: report.description,
        type: report.type,
        urgency: report.urgency,
        address: report.address,
        coordinate: {
          latitude: report.latitude,
          longitude: report.longitude
        },
        image: report.image_url,
        status: report.status,
        date: new Date(report.created_at).toLocaleDateString('ru-RU'),
        time: new Date(report.created_at).toLocaleTimeString('ru-RU'),
        userId: report.user_id,
        userName: report.users.name,
        likesCount: report.likes_count,
        commentsCount: report.comments_count
      }
    });

  } catch (error) {
    console.error('Create report error:', error);
    res.status(500).json({ error: 'Ошибка при создании отчета' });
  }
});

// Получение всех отчетов
app.get('/api/reports', async (req, res) => {
  try {
    const { page = 1, limit = 50, type, status } = req.query;
    const offset = (page - 1) * limit;

    let query = supabase
      .from('reports')
      .select(`
        *,
        users:user_id (name, email),
        likes:report_likes(count),
        comments:comments(count)
      `, { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(offset, offset + limit - 1);

    // Фильтры
    if (type) {
      query = query.eq('type', type);
    }
    if (status) {
      query = query.eq('status', status);
    }

    const { data: reports, error, count } = await query;

    if (error) throw error;

    const formattedReports = reports.map(report => ({
      id: report.id,
      title: report.title,
      description: report.description,
      type: report.type,
      urgency: report.urgency,
      address: report.address,
      coordinate: {
        latitude: report.latitude,
        longitude: report.longitude
      },
      image: report.image_url,
      status: report.status,
      date: new Date(report.created_at).toLocaleDateString('ru-RU'),
      time: new Date(report.created_at).toLocaleTimeString('ru-RU'),
      userId: report.user_id,
      userName: report.users.name,
      likesCount: report.likes[0]?.count || 0,
      commentsCount: report.comments[0]?.count || 0
    }));

    res.json({
      reports: formattedReports,
      total: count,
      page: parseInt(page),
      totalPages: Math.ceil(count / limit)
    });

  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: 'Ошибка при получении отчетов' });
  }
});

// Получение отчетов пользователя
app.get('/api/users/reports', authenticateToken, async (req, res) => {
  try {
    const { data: reports, error } = await supabase
      .from('reports')
      .select('*')
      .eq('user_id', req.user.userId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const formattedReports = reports.map(report => ({
      id: report.id,
      title: report.title,
      description: report.description,
      type: report.type,
      urgency: report.urgency,
      address: report.address,
      coordinate: {
        latitude: report.latitude,
        longitude: report.longitude
      },
      image: report.image_url,
      status: report.status,
      date: new Date(report.created_at).toLocaleDateString('ru-RU'),
      time: new Date(report.created_at).toLocaleTimeString('ru-RU')
    }));

    res.json(formattedReports);

  } catch (error) {
    console.error('Get user reports error:', error);
    res.status(500).json({ error: 'Ошибка при получении отчетов' });
  }
});

// Лайк отчета
app.post('/api/reports/:id/like', authenticateToken, async (req, res) => {
  try {
    const reportId = req.params.id;

    // Проверка существования лайка
    const { data: existingLike } = await supabase
      .from('report_likes')
      .select('id')
      .eq('user_id', req.user.userId)
      .eq('report_id', reportId)
      .single();

    if (existingLike) {
      // Удаление лайка
      await supabase
        .from('report_likes')
        .delete()
        .eq('id', existingLike.id);
    } else {
      // Добавление лайка
      await supabase
        .from('report_likes')
        .insert([
          {
            user_id: req.user.userId,
            report_id: reportId
          }
        ]);
    }

    // Получение обновленного количества лайков
    const { data: likes } = await supabase
      .from('report_likes')
      .select('id', { count: 'exact' })
      .eq('report_id', reportId);

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
    // Получение количества отчетов пользователя
    const { data: reports, error: reportsError } = await supabase
      .from('reports')
      .select('id', { count: 'exact' })
      .eq('user_id', userId);

    if (reportsError) throw reportsError;

    const reportsCount = reports.length;
    const points = reportsCount * 50;
    const level = Math.floor(points / 200) + 1;

    // Определение достижений
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
  console.error(error.stack);
  res.status(500).json({ error: 'Что-то пошло не так!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Маршрут не найден' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});
