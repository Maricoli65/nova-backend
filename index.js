const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');
const Anthropic = require('@anthropic-ai/sdk');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function inicializarBaseDeDatos() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        correo VARCHAR(255) UNIQUE NOT NULL,
        clave_hash VARCHAR(255),
        plan VARCHAR(50) DEFAULT 'ninguno',
        mensajes_usados INTEGER DEFAULT 0,
        limite_mensajes INTEGER DEFAULT 0,
        fecha_pago TIMESTAMP,
        sesion_activa VARCHAR(500),
        creado_en TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log('Base de datos lista: tabla usuarios verificada/creada');
  } catch (error) {
    console.error('Error creando la base de datos:', error);
  }
}

inicializarBaseDeDatos();

app.use(helmet());

const whitelist = ['https://nova-venezuela.net', 'https://clenovadigitalstudio.com'];
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Bloqueado por políticas de seguridad'));
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '10kb' }));
app.use(xss());

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

async function verificarSesion(req, res, next) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No has iniciado sesión.' });
    }

    const datos = jwt.verify(token, JWT_SECRET);
    const resultado = await pool.query(
      `SELECT sesion_activa FROM usuarios WHERE correo = $1`,
      [datos.correo]
    );

    if (resultado.rows.length === 0 || resultado.rows[0].sesion_activa !== token) {
      return res.status(401).json({ error: 'Tu sesión se cerró porque iniciaste sesión en otro dispositivo.' });
    }

    req.correoUsuario = datos.correo;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Sesión inválida o expirada.' });
  }
}

app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Nova backend operativo y seguro.'
  });
});

app.post('/api/registrar-correo', async (req, res) => {
  try {
    const { correo } = req.body;
    if (!correo) {
      return res.status(400).json({ error: 'El correo es obligatorio.' });
    }
    await pool.query(
      `INSERT INTO usuarios (correo) VALUES ($1) ON CONFLICT (correo) DO NOTHING`,
      [correo]
    );
    res.status(200).json({ status: 'success', mensaje: 'Correo registrado' });
  } catch (error) {
    console.error('Error registrando correo:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.post('/api/crear-clave', async (req, res) => {
  try {
    const { correo, clave } = req.body;
    if (!correo || !clave) {
      return res.status(400).json({ error: 'Correo y clave son obligatorios.' });
    }
    if (clave.length < 6) {
      return res.status(400).json({ error: 'La clave debe tener al menos 6 caracteres.' });
    }

    const claveHash = await bcrypt.hash(clave, 10);
    await pool.query(
      `UPDATE usuarios SET clave_hash = $1 WHERE correo = $2`,
      [claveHash, correo]
    );

    res.status(200).json({ status: 'success', mensaje: 'Clave creada correctamente' });
  } catch (error) {
    console.error('Error creando clave:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.post('/api/iniciar-sesion', async (req, res) => {
  try {
    const { correo, clave } = req.body;
    if (!correo || !clave) {
      return res.status(400).json({ error: 'Correo y clave son obligatorios.' });
    }

    const resultado = await pool.query(
      `SELECT * FROM usuarios WHERE correo = $1`,
      [correo]
    );

    if (resultado.rows.length === 0 || !resultado.rows[0].clave_hash) {
      return res.status(401).json({ error: 'Correo o clave incorrectos.' });
    }

    const usuario = resultado.rows[0];
    const claveValida = await bcrypt.compare(clave, usuario.clave_hash);
    if (!claveValida) {
      return res.status(401).json({ error: 'Correo o clave incorrectos.' });
    }

    if (usuario.plan === 'ninguno') {
      return res.status(403).json({ error: 'No tienes un plan activo. Suscríbete primero.' });
    }

    const nuevoToken = jwt.sign({ correo }, JWT_SECRET, { expiresIn: '30d' });

    await pool.query(
      `UPDATE usuarios SET sesion_activa = $1 WHERE correo = $2`,
      [nuevoToken, correo]
    );

    res.status(200).json({
      status: 'success',
      token: nuevoToken,
      plan: usuario.plan,
      mensajesUsados: usuario.mensajes_usados,
      limiteMensajes: usuario.limite_mensajes
    });
  } catch (error) {
    console.error('Error en inicio de sesión:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.post('/api/cerrar-sesion', verificarSesion, async (req, res) => {
  try {
    await pool.query(
      `UPDATE usuarios SET sesion_activa = NULL WHERE correo = $1`,
      [req.correoUsuario]
    );
    res.status(200).json({ status: 'success', mensaje: 'Sesión cerrada correctamente' });
  } catch (error) {
    console.error('Error cerrando sesión:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.post('/api/chat', verificarSesion, async (req, res) => {
  try {
    const { mensaje } = req.body;
    if (!mensaje) {
      return res.status(400).json({ error: 'El mensaje es obligatorio.' });
    }

    const resultado = await pool.query(
      `SELECT mensajes_usados, limite_mensajes FROM usuarios WHERE correo = $1`,
      [req.correoUsuario]
    );
    const usuario = resultado.rows[0];

    if (usuario.mensajes_usados >= usuario.limite_mensajes) {
      return res.status(403).json({ error: 'Alcanzaste el límite de tu plan este mes.' });
    }

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 1024,
      messages: [{ role: 'user', content: mensaje }],
    });

    await pool.query(
      `UPDATE usuarios SET mensajes_usados = mensajes_usados + 1 WHERE correo = $1`,
      [req.correoUsuario]
    );

    res.status(200).json({
      status: 'success',
      respuesta: response.content[0].text
    });
  } catch (error) {
    console.error('Error en el servidor:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

const LIMITES_PLAN = {
  'basico': 700,
  'emprendedor': 2000,
  'negocios': 6000
};

app.post('/api/webhook-paypal', async (req, res) => {
  try {
    const evento = req.body;
    const tipoEvento = evento.event_type;

    console.log('Evento de PayPal recibido:', tipoEvento);

    if (tipoEvento === 'BILLING.SUBSCRIPTION.ACTIVATED') {
      const correo = evento.resource.subscriber.email_address;
      const idPlanPayPal = evento.resource.plan_id;

      let planNova = 'basico';
      if (idPlanPayPal === 'P-1DM147813T2019908NKBW77A') planNova = 'emprendedor';
      if (idPlanPayPal === 'P-7NG33178F9678730CNKBXCJA') planNova = 'negocios';

      await pool.query(
        `INSERT INTO usuarios (correo, plan, mensajes_usados, limite_mensajes, fecha_pago)
         VALUES ($1, $2, 0, $3, NOW())
         ON CONFLICT (correo)
         DO UPDATE SET plan = $2, mensajes_usados = 0, limite_mensajes = $3, fecha_pago = NOW()`,
        [correo, planNova, LIMITES_PLAN[planNova]]
      );

      console.log('Plan activado para:', correo, '-', planNova);
    }

    if (tipoEvento === 'BILLING.SUBSCRIPTION.CANCELLED') {
      const correo = evento.resource.subscriber.email_address;

      await pool.query(
        `UPDATE usuarios SET plan = 'ninguno', limite_mensajes = 0, sesion_activa = NULL WHERE correo = $1`,
        [correo]
      );

      console.log('Plan cancelado para:', correo);
    }

    res.status(200).json({ status: 'success' });
  } catch (error) {
    console.error('Error procesando webhook de PayPal:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor de Nova corriendo en el puerto ${PORT}`);
});



  




