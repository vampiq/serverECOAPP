const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
  origin: ['http://localhost:3000', 'exp://localhost:19000', 'https://your-app.netlify.app'],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ Supabase credentials are missing!');
  console.log('Please set SUPABASE_URL and SUPABASE_ANON_KEY environment variables');
}

const supabase = createClient(supabaseUrl, supabaseKey);

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'eco-map-secret-key-northflank';

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
  userName: report.users?.name || 'Пользователь'
});

// Routes

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Eco Map API работает на Northflank! 🚀',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
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

    if (name.trim().length < 2) {
      return res.status(400).json({ error: 'Имя должно содержать минимум 2 символа' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // Проверка существующего пользователя
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', normalizedEmail)
      .single();

    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
    }

    // Хеширование пароля
    const passwordHash = await bcrypt.hash(password, 12);

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

// Создание отчета
app.post('/api/reports', async (req, res) => {
  try {
    const {
      title,
      description,
      type,
      urgency,
      address,
      latitude,
      longitude,
      userId
    } = req.body;

    // Валидация
    if (!title || !type || !urgency || !address || !latitude || !longitude || !userId) {
      return res.status(400).json({ error: 'Все обязательные поля должны быть заполнены' });
    }

    if (title.trim().length < 5) {
      return res.status(400).json({ error: 'Заголовок должен содержать минимум 5 символов' });
    }

    // Создание отчета
    const { data: report, error } = await supabase
      .from('reports')
      .insert([{
        user_id: userId,
        title: title.trim(),
        description: description?.trim(),
        type,
        urgency,
        address: address.trim(),
        latitude: parseFloat(latitude),
        longitude: parseFloat(longitude),
        status: 'active'
      }])
      .select(`
        *,
        users:user_id (name)
      `)
      .single();

    if (error) throw error;

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
    const { data: reports, error } = await supabase
      .from('reports')
      .select(`
        *,
        users:user_id (name)
      `)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) throw error;

    const formattedReports = reports.map(report => formatReportResponse(report));

    res.json({
      success: true,
      reports: formattedReports
    });

  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: 'Ошибка при получении отчетов' });
  }
});

// Получение отчетов пользователя
app.get('/api/users/:userId/reports', async (req, res) => {
  try {
    const { userId } = req.params;

    const { data: reports, error } = await supabase
      .from('reports')
      .select('*')
      .eq('user_id', userId)
      .order('created_at', { ascending: false });

    if (error) throw error;

    const formattedReports = reports.map(report => formatReportResponse(report));

    res.json({
      success: true,
      reports: formattedReports
    });

  } catch (error) {
    console.error('Get user reports error:', error);
    res.status(500).json({ error: 'Ошибка при получении отчетов пользователя' });
  }
});

// Получение статистики
app.get('/api/stats', async (req, res) => {
  try {
    // Количество отчетов
    const { count: totalReports, error: reportsError } = await supabase
      .from('reports')
      .select('*', { count: 'exact', head: true });

    // Количество пользователей
    const { count: totalUsers, error: usersError } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });

    if (reportsError || usersError) throw reportsError || usersError;

    res.json({
      success: true,
      stats: {
        totalReports,
        totalUsers,
        lastUpdated: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Ошибка при получении статистики' });
  }
});

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

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Eco Map Server запущен на порту ${PORT}`);
  console.log(`📍 Northflank Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://0.0.0.0:${PORT}/api/health`);
});
