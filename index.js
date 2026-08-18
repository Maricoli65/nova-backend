const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
const PORT = process.env.PORT || 3000;

// Seguridad básica con Helmet (Cabeceras HTTP seguras)
app.use(helmet());

// Configuración de CORS - solo permite que TU web se conecte, no cualquiera
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

// Procesamiento de JSON con límite de tamaño (evita ataques de sobrecarga)
app.use(express.json({ limit: '10kb' }));

// Sanitización contra ataques XSS
app.use(xss());

// Conexión con Claude (la clave vive solo aquí, en el servidor)
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// Ruta de prueba (Health Check)
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Nova backend operativo y seguro.'
  });
});

// Ruta principal: recibe el mensaje del usuario y responde con Claude
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

app.listen(PORT, () => {
  console.log(`Servidor de Nova corriendo en el puerto ${PORT}`);
});

  




