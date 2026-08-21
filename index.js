const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');
const Anthropic = require('@anthropic-ai/sdk');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

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
        plan VARCHAR(50) DEFAULT 'ninguno',
        mensajes_usados INTEGER DEFAULT 0,
        limite_mensajes INTEGER DEFAULT 0,
        fecha_pago TIMESTAMP,
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

const whitelist = ['https://novavenezuela.net', 'https://clenovadigitalstudio.com'];
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

app.post('/api/chat', async (req, res) => {
  try {
    const { mensaje } = req.body;
    if (!mensaje) {
      return res.status(400).json({ error: 'El mensaje es obligatorio.' });
    }
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 1024,
      messages: [{ role: 'user', content: mensaje }],
    });
    res.status(200).json({
      status: 'success',
      respuesta: response.content[0].text
    });
  } catch (error) {
    console.error('Error en el servidor:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Límites de mensajes según cada plan de Nova
const LIMITES_PLAN = {
  'basico': 700,
  'emprendedor': 2000,
  'negocios': 6000
};

// Webhook de PayPal: recibe la notificación automática cuando alguien paga
app.post('/api/webhook-paypal', async (req, res) => {
  try {
    const evento = req.body;
    const tipoEvento = evento.event_type;

    console.log('Evento de PayPal recibido:', tipoEvento);

    // Cuando se activa una nueva suscripción
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

    // Cuando se cancela una suscripción
    if (tipoEvento === 'BILLING.SUBSCRIPTION.CANCELLED') {
      const correo = evento.resource.subscriber.email_address;

      await pool.query(
        `UPDATE usuarios SET plan = 'ninguno', limite_mensajes = 0 WHERE correo = $1`,
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


  




