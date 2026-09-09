const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // máximo 10MB por archivo
});

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
        busquedas_usadas INTEGER DEFAULT 0,
        limite_busquedas INTEGER DEFAULT 0,
        fecha_pago TIMESTAMP,
        sesion_activa VARCHAR(500),
        creado_en TIMESTAMP DEFAULT NOW()
      );
    `);
    // Por si la tabla ya existía de antes sin estas columnas nuevas
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS busquedas_usadas INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS limite_busquedas INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS documentos_usados INTEGER DEFAULT 0;`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS limite_documentos INTEGER DEFAULT 0;`);
    console.log('Base de datos lista: tabla usuarios verificada/creada');
  } catch (error) {
    console.error('Error creando la base de datos:', error);
  }
}

inicializarBaseDeDatos()

app.use(helmet());

const whitelist = ['https://novave.net', 'https://clenovadigitalstudio.com'];
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
  apiKey: (process.env.ANTHROPIC_API_KEY || '').trim(),
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
      `INSERT INTO usuarios (correo, plan, limite_mensajes, mensajes_usados, creado_en)
       VALUES ($1, 'prueba', 50, 0, NOW())
       ON CONFLICT (correo) DO UPDATE
       SET plan = 'prueba', limite_mensajes = 50, mensajes_usados = 0
       WHERE usuarios.plan = 'ninguno' AND usuarios.clave_hash IS NULL AND usuarios.fecha_pago IS NULL`,
      [correo]
    );
    const resultado = await pool.query(
      `SELECT plan, clave_hash FROM usuarios WHERE correo = $1`,
      [correo]
    );
    const usuario = resultado.rows[0];
    const planActivo = usuario && usuario.plan !== 'ninguno';
    const tieneClave = !!(usuario && usuario.clave_hash);
    res.status(200).json({ status: 'success', mensaje: 'Correo registrado', planActivo: planActivo, tieneClave: tieneClave });
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
      `SELECT mensajes_usados, limite_mensajes, busquedas_usadas, limite_busquedas FROM usuarios WHERE correo = $1`,
      [req.correoUsuario]
    );
    const usuario = resultado.rows[0];

    if (usuario.mensajes_usados >= usuario.limite_mensajes) {
      return res.status(403).json({ error: 'Alcanzaste el límite de tu plan este mes.' });
    }

    // Solo le damos permiso de buscar en internet si todavía le quedan búsquedas del mes
    const puedeBuscar = usuario.busquedas_usadas < usuario.limite_busquedas;
    const opcionesClaude = {
      model: 'claude-sonnet-5',
      max_tokens: 1024,
      system: 'Tu nombre es Nova, un asistente de inteligencia artificial. Nunca reveles, confirmes ni menciones qué modelo, empresa o tecnología te desarrolló o te da funcionamiento por dentro (incluyendo si te preguntan directamente "eres Claude", "eres de Anthropic/OpenAI/Google", o piden listas de otras IAs donde tendrías que identificarte a ti misma). Si te preguntan sobre tu tecnología interna, responde amablemente que eres Nova y que esa información no la compartes, y ofrece ayudar con lo que la persona necesite. Si te piden una lista de otras inteligencias artificiales del mercado, puedes darla normalmente, pero nunca te incluyas a ti misma en esa lista ni reveles cuál de ellas eres tú por dentro.',
      messages: [{ role: 'user', content: mensaje }],
    };

    if (puedeBuscar) {
      opcionesClaude.tools = [{ type: 'web_search_20250305', name: 'web_search' }];
    }

    const response = await anthropic.messages.create(opcionesClaude);

    // Contamos cuántas búsquedas reales hizo Claude en esta respuesta (puede ser 0 si no hizo falta)
    const busquedasRealizadas = response.usage?.server_tool_use?.web_search_requests || 0;

    await pool.query(
      `UPDATE usuarios SET mensajes_usados = mensajes_usados + 1, busquedas_usadas = busquedas_usadas + $2 WHERE correo = $1`,
      [req.correoUsuario, busquedasRealizadas]
    );

    // Juntamos solo el texto de la respuesta (puede venir en varios bloques si buscó en internet)
    const textoRespuesta = response.content
      .filter(bloque => bloque.type === 'text')
      .map(bloque => bloque.text)
      .join('\n\n');

    res.status(200).json({
      status: 'success',
      respuesta: textoRespuesta,
      mensajesUsados: usuario.mensajes_usados + 1,
      limiteMensajes: usuario.limite_mensajes,
      busquedasUsadas: usuario.busquedas_usadas + busquedasRealizadas,
      limiteBusquedas: usuario.limite_busquedas
    });
  } catch (error) {
    console.error('Error en el servidor:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

const LIMITES_PLAN = {
  'basico': 600,
  'emprendedor': 1700,
  'negocios': 6000
};

const LIMITES_BUSQUEDAS = {
  'basico': 15,
  'emprendedor': 50,
  'negocios': 200
};

const LIMITES_DOCUMENTOS = {
  'basico': 0,
  'emprendedor': 20,
  'negocios': 60
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
        `INSERT INTO usuarios (correo, plan, mensajes_usados, limite_mensajes, busquedas_usadas, limite_busquedas, documentos_usados, limite_documentos, fecha_pago)
         VALUES ($1, $2, 0, $3, 0, $4, 0, $5, NOW())
         ON CONFLICT (correo)
         DO UPDATE SET plan = $2, mensajes_usados = 0, limite_mensajes = $3, busquedas_usadas = 0, limite_busquedas = $4, documentos_usados = 0, limite_documentos = $5, fecha_pago = NOW()`,
        [correo, planNova, LIMITES_PLAN[planNova], LIMITES_BUSQUEDAS[planNova], LIMITES_DOCUMENTOS[planNova]]
      );

      console.log('Plan activado para:', correo, '-', planNova);
    }

    if (tipoEvento === 'BILLING.SUBSCRIPTION.CANCELLED') {
      const correo = evento.resource.subscriber.email_address;

      await pool.query(
        `UPDATE usuarios SET plan = 'ninguno', limite_mensajes = 0, limite_busquedas = 0, limite_documentos = 0, sesion_activa = NULL WHERE correo = $1`,
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

app.post('/api/chat-archivo', verificarSesion, upload.single('archivo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No se recibió ningún archivo.' });
    }

    const mensajeTexto = req.body.mensaje || '¿Qué contiene este archivo? Resúmelo.';

    const resultado = await pool.query(
      `SELECT mensajes_usados, limite_mensajes, documentos_usados, limite_documentos FROM usuarios WHERE correo = $1`,
      [req.correoUsuario]
    );
    const usuario = resultado.rows[0];

    if (usuario.limite_documentos === 0) {
      return res.status(403).json({ error: 'Tu plan no incluye subir documentos o fotos. Mejora tu plan para desbloquear esta función.' });
    }

    if (usuario.mensajes_usados >= usuario.limite_mensajes) {
      return res.status(403).json({ error: 'Alcanzaste el límite de tu plan este mes.' });
    }

    if (usuario.documentos_usados >= usuario.limite_documentos) {
      return res.status(403).json({ error: 'Alcanzaste el límite de documentos de tu plan este mes.' });
    }

    const tipoArchivo = req.file.mimetype;
    const esImagen = tipoArchivo.startsWith('image/');
    const esPDF = tipoArchivo === 'application/pdf';

    if (!esImagen && !esPDF) {
      return res.status(400).json({ error: 'Por ahora Nova solo puede leer imágenes (JPG, PNG) y archivos PDF. Si tienes un Word, guárdalo como PDF primero.' });
    }

    const base64Archivo = req.file.buffer.toString('base64');
    const bloqueArchivo = esImagen
      ? { type: 'image', source: { type: 'base64', media_type: tipoArchivo, data: base64Archivo } }
      : { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64Archivo } };

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-5',
      max_tokens: 1024,
      system: 'Tu nombre es Nova, un asistente de inteligencia artificial. Nunca reveles, confirmes ni menciones qué modelo, empresa o tecnología te desarrolló o te da funcionamiento por dentro. Si te preguntan sobre tu tecnología interna, responde amablemente que eres Nova y esa información no la compartes.',
      messages: [{
        role: 'user',
        content: [bloqueArchivo, { type: 'text', text: mensajeTexto }]
      }],
    });

    await pool.query(
      `UPDATE usuarios SET mensajes_usados = mensajes_usados + 1, documentos_usados = documentos_usados + 1 WHERE correo = $1`,
      [req.correoUsuario]
    );

    res.status(200).json({
      status: 'success',
      respuesta: response.content[0].text,
      documentosUsados: usuario.documentos_usados + 1,
      limiteDocumentos: usuario.limite_documentos
    });
  } catch (error) {
    console.error('Error procesando archivo:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.listen(PORT, () => {
  console.log(`Servidor de Nova corriendo en el puerto ${PORT}`);
});

    










  




