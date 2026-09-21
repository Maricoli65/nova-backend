const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const xss = require('xss-clean');
const multer = require('multer');
const Anthropic = require('@anthropic-ai/sdk');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');
const Sentry = require('@sentry/node');

// ============================================
// SENTRY (monitoreo de errores en producción)
// Avisa por correo apenas algo se rompe, en vez de enterarse por queja de cliente
// ============================================
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  tracesSampleRate: 0.1,
});

const resend = new Resend(process.env.RESEND_API_KEY);

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

// ============================================
// PROMPT DE SISTEMA UNIFICADO
// (antes estaba duplicado en /api/chat y /api/chat-archivo)
// ============================================
const SYSTEM_PROMPT_NOVA = 'Tu nombre es Nova, un asistente de inteligencia artificial. Tu tono es profesional, cálido y claro, como el de un asistente serio de nivel corporativo. No uses emojis ni emoticonos en tus respuestas, salvo que el usuario los use primero y el contexto lo amerite; incluso en ese caso, úsalos con mucha moderación. Esta regla es estricta: aunque tus respuestas anteriores en esta misma conversación contengan emojis, NO los imites — de ahora en adelante responde siempre sin emojis. Nunca reveles, confirmes ni menciones qué modelo, empresa o tecnología te desarrolló o te da funcionamiento por dentro (incluyendo si te preguntan directamente "eres Claude", "eres de Anthropic/OpenAI/Google", o piden listas de otras IAs donde tendrías que identificarte a ti misma). Si te preguntan sobre tu tecnología interna, responde amablemente que eres Nova y que esa información no la compartes, y ofrece ayudar con lo que la persona necesite. Si te piden una lista de otras inteligencias artificiales del mercado, puedes darla normalmente, pero nunca te incluyas a ti misma en esa lista ni reveles cuál de ellas eres tú por dentro.';

// Cuántos intercambios (usuario+Nova) se guardan tal cual antes de resumirlos
const INTERCAMBIOS_ANTES_DE_RESUMIR = 6;

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

    // --- Columnas de memoria (reconstruidas 13 sept 2026) ---
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS resumen_memoria TEXT DEFAULT '';`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS datos_fijados TEXT DEFAULT '';`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS historial_reciente JSONB DEFAULT '[]'::jsonb;`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS contador_intercambios INTEGER DEFAULT 0;`);

    // --- Columna de cuenta administradora (sin límites) ---
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS es_admin BOOLEAN DEFAULT FALSE;`);

    // --- Columnas para "Olvidé mi contraseña" (14 sept 2026) ---
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS token_recuperacion VARCHAR(255);`);
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS token_recuperacion_vence TIMESTAMP;`);

    // --- Columna de bloqueo de cuenta puntual (15 sept 2026) ---
    // Para congelar una cuenta específica en caso de robo de clave o abuso, sin apagar el resto de Nova
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS cuenta_bloqueada BOOLEAN DEFAULT FALSE;`);

    // --- Tanda 3 (20 sept 2026): Mi cuenta + historial de chats ---
    // Nombre del cliente (opcional, lo escribe él mismo en la pantalla Mi cuenta)
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS nombre VARCHAR(60) DEFAULT '';`);
    // Apunta al chat que el usuario tiene abierto ahora mismo (NULL = todavía no hay)
    await pool.query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS conversacion_activa INTEGER;`);
    // Tabla de conversaciones guardadas: cada chat del usuario, con todos sus mensajes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS conversaciones (
        id SERIAL PRIMARY KEY,
        correo VARCHAR(255) NOT NULL,
        titulo VARCHAR(120) NOT NULL,
        mensajes JSONB DEFAULT '[]'::jsonb,
        creado_en TIMESTAMP DEFAULT NOW(),
        actualizado_en TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_conversaciones_correo ON conversaciones (correo, actualizado_en DESC);`);

    console.log('Base de datos lista: tabla usuarios verificada/creada');
  } catch (error) {
    console.error('Error creando la base de datos:', error);
  }
}

inicializarBaseDeDatos()

app.use(helmet());

const whitelist = ['https://novave.net'];
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

// ============================================
// RATE LIMITING (protección contra fuerza bruta y saturación)
// ============================================
// General: para todas las rutas /api/, un límite amplio contra saturación del servidor
const limitadorGeneral = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 solicitudes por IP cada 15 minutos
  message: { error: 'Demasiadas solicitudes. Espera unos minutos e intenta de nuevo.' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limitadorGeneral);

// Estricto: para login, crear clave y recuperación — evita que adivinen contraseñas a la fuerza
const limitadorEstricto = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 8, // 8 intentos por IP cada 15 minutos
  message: { error: 'Demasiados intentos. Por seguridad, espera 15 minutos antes de volver a intentar.' },
  standardHeaders: true,
  legacyHeaders: false,
});

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
      `SELECT sesion_activa, cuenta_bloqueada FROM usuarios WHERE correo = $1`,
      [datos.correo]
    );

    if (resultado.rows.length === 0 || resultado.rows[0].sesion_activa !== token) {
      return res.status(401).json({ error: 'Tu sesión se cerró porque iniciaste sesión en otro dispositivo.' });
    }

    if (resultado.rows[0].cuenta_bloqueada) {
      return res.status(403).json({ error: 'Esta cuenta está bloqueada temporalmente. Contacta a soporte@novave.net.' });
    }

    req.correoUsuario = datos.correo;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Sesión inválida o expirada.' });
  }
}

// ============================================
// FUNCIONES DE MEMORIA (reconstruidas 13 sept 2026)
// ============================================

function detectarPeticionDeRecordar(mensaje) {
  return /recu[eé]rdame\s+(esto|que)?/i.test(mensaje);
}

async function guardarDatoFijado(correo, mensaje) {
  await pool.query(
    `UPDATE usuarios
     SET datos_fijados = CASE
       WHEN datos_fijados IS NULL OR datos_fijados = '' THEN $2
       ELSE datos_fijados || E'\n' || $2
     END
     WHERE correo = $1`,
    [correo, `- ${mensaje.trim()}`]
  );
}

async function resumirMemoria(resumenActual, historialReciente) {
  const textoHistorial = historialReciente
    .map(intercambio => `Usuario: ${intercambio.usuario}\nNova: ${intercambio.nova}`)
    .join('\n\n');

  const promptResumen = `Aquí tienes el resumen de una conversación hasta ahora, y los intercambios más recientes que todavía no están resumidos. Actualiza el resumen para que incluya lo importante de los nuevos intercambios, en un párrafo breve y claro (máximo 150 palabras), en español. No inventes nada que no esté en el texto.

RESUMEN ANTERIOR:
${resumenActual || '(todavía no hay resumen, esta es la primera vez)'}

INTERCAMBIOS NUEVOS:
${textoHistorial}

Responde solo con el resumen actualizado, sin preámbulo.`;

  const response = await anthropic.messages.create({
    model: 'claude-sonnet-5',
    max_tokens: 400,
    messages: [{ role: 'user', content: promptResumen }],
  });

  return response.content
    .filter(bloque => bloque.type === 'text')
    .map(bloque => bloque.text)
    .join('\n')
    .trim();
}

async function actualizarMemoriaTrasIntercambio(correo, mensajeUsuario, respuestaNova, resumenActual, historialActual, contadorActual) {
  const nuevoHistorial = [...historialActual, { usuario: mensajeUsuario, nova: respuestaNova }];
  const nuevoContador = contadorActual + 1;

  if (nuevoContador >= INTERCAMBIOS_ANTES_DE_RESUMIR) {
    try {
      const resumenActualizado = await resumirMemoria(resumenActual, nuevoHistorial);
      await pool.query(
        `UPDATE usuarios SET resumen_memoria = $1, historial_reciente = '[]'::jsonb, contador_intercambios = 0 WHERE correo = $2`,
        [resumenActualizado, correo]
      );
    } catch (error) {
      console.error('Error resumiendo memoria:', error);
      await pool.query(
        `UPDATE usuarios SET historial_reciente = $1, contador_intercambios = $2 WHERE correo = $3`,
        [JSON.stringify(nuevoHistorial), nuevoContador, correo]
      );
    }
  } else {
    await pool.query(
      `UPDATE usuarios SET historial_reciente = $1, contador_intercambios = $2 WHERE correo = $3`,
      [JSON.stringify(nuevoHistorial), nuevoContador, correo]
    );
  }
}

// ============================================
// HISTORIAL DE CHATS (Tanda 3, 20 sept 2026)
// ============================================
// Cada intercambio se guarda también en la conversación activa del usuario,
// para que pueda ver y reabrir sus chats anteriores desde el panel de las
// tres rayitas. Corre en segundo plano: si falla, se anota el error en los
// logs pero la respuesta al cliente no se afecta.

function generarTituloDeChat(mensaje) {
  const limpio = (mensaje || '').replace(/\s+/g, ' ').trim();
  if (limpio.length <= 40) return limpio || 'Nueva conversación';
  return limpio.slice(0, 40).trim() + '…';
}

async function guardarEnConversacion(correo, conversacionActiva, mensajeUsuario, respuestaNova) {
  const nuevosMensajes = [
    { rol: 'usuario', texto: mensajeUsuario },
    { rol: 'nova', texto: respuestaNova }
  ];

  if (conversacionActiva) {
    const resultado = await pool.query(
      `UPDATE conversaciones
       SET mensajes = mensajes || $1::jsonb, actualizado_en = NOW()
       WHERE id = $2 AND correo = $3`,
      [JSON.stringify(nuevosMensajes), conversacionActiva, correo]
    );
    if (resultado.rowCount > 0) return;
    // Si la conversación activa ya no existe (la borró desde otro dispositivo),
    // se cae aquí abajo y se crea una nueva con este intercambio
  }

  // Primer mensaje de un chat nuevo: nace la conversación y su título
  const creada = await pool.query(
    `INSERT INTO conversaciones (correo, titulo, mensajes) VALUES ($1, $2, $3::jsonb) RETURNING id`,
    [correo, generarTituloDeChat(mensajeUsuario), JSON.stringify(nuevosMensajes)]
  );
  await pool.query(
    `UPDATE usuarios SET conversacion_activa = $1 WHERE correo = $2`,
    [creada.rows[0].id, correo]
  );
}

function construirSystemConMemoria(resumenMemoria, datosFijados, nombreUsuario) {
  const bloqueMemoria = `Resumen de la conversación con este usuario hasta ahora: ${resumenMemoria || '(sin resumen todavía, es de las primeras conversaciones)'}

Datos que el usuario pidió explícitamente recordar: ${datosFijados || '(ninguno todavía)'}

Nombre del usuario (si lo indicó en su cuenta, úsalo con naturalidad para dirigirte a él): ${nombreUsuario || '(no lo ha indicado)'}`;

  // FECHA DEL SERVIDOR: Nova no tiene reloj propio; se le inyecta la fecha/hora
  // de Venezuela en cada llamada. Va DESPUÉS del bloque con cache para no
  // invalidar el caché del prompt cada minuto.
  const fechaVenezuela = new Date().toLocaleString('es-VE', {
    timeZone: 'America/Caracas',
    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
    hour: 'numeric', minute: '2-digit', hour12: true
  });

  return [
    { type: 'text', text: SYSTEM_PROMPT_NOVA },
    { type: 'text', text: bloqueMemoria, cache_control: { type: 'ephemeral' } },
    { type: 'text', text: `Fecha y hora actual en Venezuela: ${fechaVenezuela}.` }
  ];
}

function construirMensajesConHistorial(historialReciente, contenidoNuevo) {
  const mensajes = [];
  for (const intercambio of historialReciente) {
    mensajes.push({ role: 'user', content: intercambio.usuario });
    mensajes.push({ role: 'assistant', content: intercambio.nova });
  }
  mensajes.push({ role: 'user', content: contenidoNuevo });
  return mensajes;
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
      `INSERT INTO usuarios (correo, plan, limite_mensajes, mensajes_usados, limite_busquedas, busquedas_usadas, creado_en)
       VALUES ($1, 'prueba', 30, 0, 10, 0, NOW())
       ON CONFLICT (correo) DO UPDATE
       SET plan = 'prueba', limite_mensajes = 30, mensajes_usados = 0, limite_busquedas = 10, busquedas_usadas = 0
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

app.post('/api/iniciar-sesion', limitadorEstricto, async (req, res) => {
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

    if (usuario.cuenta_bloqueada) {
      return res.status(403).json({ error: 'Esta cuenta está bloqueada temporalmente. Contacta a soporte@novave.net.' });
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

// ============================================
// OLVIDÉ MI CONTRASEÑA (14 sept 2026)
// ============================================
const crypto = require('crypto');

app.post('/api/solicitar-recuperacion', limitadorEstricto, async (req, res) => {
  try {
    const { correo } = req.body;
    if (!correo) {
      return res.status(400).json({ error: 'El correo es obligatorio.' });
    }

    const resultado = await pool.query(`SELECT correo FROM usuarios WHERE correo = $1`, [correo]);

    // Por seguridad, siempre respondemos "listo" exista o no la cuenta —
    // así nadie puede usar este formulario para averiguar qué correos están registrados
    if (resultado.rows.length > 0) {
      const token = crypto.randomBytes(32).toString('hex');
      const vence = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

      await pool.query(
        `UPDATE usuarios SET token_recuperacion = $1, token_recuperacion_vence = $2 WHERE correo = $3`,
        [token, vence, correo]
      );

      const enlace = `https://novave.net/restablecer.html?token=${token}`;

      try {
        await resend.emails.send({
          from: 'Nova <soporte@novave.net>',
          to: correo,
          subject: 'Restablece tu contraseña de Nova',
          html: `<p>Hola,</p><p>Recibimos una solicitud para restablecer tu contraseña de Nova. Este enlace vence en 1 hora:</p><p><a href="${enlace}">${enlace}</a></p><p>Si no fuiste tú, puedes ignorar este correo — tu contraseña actual sigue funcionando.</p>`,
        });
      } catch (errorCorreo) {
        console.error('Error enviando correo de recuperación:', errorCorreo);
        Sentry.captureException(errorCorreo);
      }
    }

    res.status(200).json({ status: 'success', mensaje: 'Si el correo existe, te enviamos un enlace para restablecer tu contraseña.' });
  } catch (error) {
    console.error('Error solicitando recuperación:', error);
    Sentry.captureException(error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

app.post('/api/restablecer-clave', limitadorEstricto, async (req, res) => {
  try {
    const { token, claveNueva } = req.body;
    if (!token || !claveNueva) {
      return res.status(400).json({ error: 'Faltan datos.' });
    }
    if (claveNueva.length < 6) {
      return res.status(400).json({ error: 'La clave debe tener al menos 6 caracteres.' });
    }

    const resultado = await pool.query(
      `SELECT correo, token_recuperacion_vence FROM usuarios WHERE token_recuperacion = $1`,
      [token]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).json({ error: 'Este enlace no es válido. Solicita uno nuevo.' });
    }

    const usuario = resultado.rows[0];
    if (new Date() > new Date(usuario.token_recuperacion_vence)) {
      return res.status(400).json({ error: 'Este enlace ya venció. Solicita uno nuevo.' });
    }

    const claveHash = await bcrypt.hash(claveNueva, 10);
    await pool.query(
      `UPDATE usuarios
       SET clave_hash = $1, token_recuperacion = NULL, token_recuperacion_vence = NULL, sesion_activa = NULL
       WHERE correo = $2`,
      [claveHash, usuario.correo]
    );

    res.status(200).json({ status: 'success', mensaje: 'Contraseña actualizada correctamente. Ya puedes iniciar sesión.' });
  } catch (error) {
    console.error('Error restableciendo clave:', error);
    Sentry.captureException(error);
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

// Nuevo Chat: reinicia el hilo de conversación actual (historial reciente),
// sin borrar lo que Nova ya sabe del usuario (resumen de memoria, "recuérdame esto").
// Mismo comportamiento que "New Chat" en ChatGPT/Claude: empieza fresco el tema,
// pero la personalización de largo plazo se mantiene.
app.post('/api/nuevo-chat', verificarSesion, async (req, res) => {
  try {
    await pool.query(
      `UPDATE usuarios SET historial_reciente = '[]'::jsonb, contador_intercambios = 0, conversacion_activa = NULL WHERE correo = $1`,
      [req.correoUsuario]
    );
    res.status(200).json({ status: 'success', mensaje: 'Nuevo chat iniciado.' });
  } catch (error) {
    console.error('Error iniciando nuevo chat:', error);
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
      `SELECT mensajes_usados, limite_mensajes, busquedas_usadas, limite_busquedas,
              resumen_memoria, datos_fijados, historial_reciente, contador_intercambios, es_admin,
              nombre, conversacion_activa
       FROM usuarios WHERE correo = $1`,
      [req.correoUsuario]
    );
    const usuario = resultado.rows[0];
    const esAdmin = usuario.es_admin === true;

    if (!esAdmin && usuario.mensajes_usados >= usuario.limite_mensajes) {
      return res.status(403).json({ error: 'Alcanzaste el límite de tu plan este mes.' });
    }

    // COMANDO DE ADMINISTRADORA: si la cuenta admin escribe "/clientes" en el chat,
    // Nova responde el resumen de clientes por plan directo desde la base de datos.
    // No llama a la API (costo cero) y no toca la memoria ni los contadores.
    if (esAdmin && mensaje.trim().toLowerCase() === '/clientes') {
      const NOMBRES_PLAN = { emprendedor: 'Pro', negocios: 'Plus', basico: 'Básico', prueba: 'Prueba gratis', ninguno: 'Sin plan (cancelados)' };
      const conteo = await pool.query(
        `SELECT plan, COUNT(*)::int AS cantidad FROM usuarios GROUP BY plan ORDER BY cantidad DESC`
      );
      let totalClientes = 0;
      const lineas = conteo.rows.map(fila => {
        totalClientes += fila.cantidad;
        const nombre = NOMBRES_PLAN[fila.plan] || fila.plan;
        return `• ${nombre}: ${fila.cantidad}`;
      });
      const resumenClientes = `Resumen de clientes por plan\n\n${lineas.join('\n')}\n\nTotal de cuentas: ${totalClientes}`;
      return res.status(200).json({
        status: 'success',
        respuesta: resumenClientes,
        mensajesUsados: usuario.mensajes_usados,
        limiteMensajes: usuario.limite_mensajes,
        busquedasUsadas: usuario.busquedas_usadas,
        limiteBusquedas: usuario.limite_busquedas
      });
    }

    if (detectarPeticionDeRecordar(mensaje)) {
      await guardarDatoFijado(req.correoUsuario, mensaje);
    }

    const puedeBuscar = esAdmin || usuario.busquedas_usadas < usuario.limite_busquedas;

    const historialReciente = usuario.historial_reciente || [];

    const opcionesClaude = {
      model: 'claude-sonnet-5',
      max_tokens: 700,
      system: construirSystemConMemoria(usuario.resumen_memoria, usuario.datos_fijados, usuario.nombre),
      messages: construirMensajesConHistorial(historialReciente, mensaje),
    };

    if (puedeBuscar) {
      opcionesClaude.tools = [{ type: 'web_search_20250305', name: 'web_search' }];
    }

    const response = await anthropic.messages.create(opcionesClaude);

    const busquedasRealizadas = response.usage?.server_tool_use?.web_search_requests || 0;

    await pool.query(
      `UPDATE usuarios SET mensajes_usados = mensajes_usados + 1, busquedas_usadas = busquedas_usadas + $2 WHERE correo = $1`,
      [req.correoUsuario, busquedasRealizadas]
    );

    const textoRespuesta = response.content
      .filter(bloque => bloque.type === 'text')
      .map(bloque => bloque.text)
      .join('\n\n');

    // FUENTES DE BÚSQUEDA: la API ya devuelve qué páginas consultó Nova
    // (antes el backend las descartaba). Se recogen de las citas de la
    // respuesta, sin repetir, máximo 8, y se envían al navegador para
    // que el frontend las dibuje debajo de la respuesta.
    const fuentes = [];
    const urlsVistas = new Set();
    for (const bloque of response.content) {
      if (bloque.type === 'text' && Array.isArray(bloque.citations)) {
        for (const cita of bloque.citations) {
          if (cita.url && !urlsVistas.has(cita.url) && fuentes.length < 8) {
            urlsVistas.add(cita.url);
            fuentes.push({ titulo: cita.title || cita.url, url: cita.url });
          }
        }
      }
    }

    actualizarMemoriaTrasIntercambio(
      req.correoUsuario,
      mensaje,
      textoRespuesta,
      usuario.resumen_memoria,
      historialReciente,
      usuario.contador_intercambios || 0
    ).catch(error => console.error('Error actualizando memoria:', error));

    guardarEnConversacion(req.correoUsuario, usuario.conversacion_activa, mensaje, textoRespuesta)
      .catch(error => console.error('Error guardando en conversación:', error));

    res.status(200).json({
      status: 'success',
      respuesta: textoRespuesta,
      fuentes: fuentes,
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
  'emprendedor': 340,
  'negocios': 550
};

const LIMITES_BUSQUEDAS = {
  'emprendedor': 25,
  'negocios': 100
};

const LIMITES_DOCUMENTOS = {
  'emprendedor': 10,
  'negocios': 30
};

app.post('/api/webhook-paypal', async (req, res) => {
  try {
    const evento = req.body;
    const tipoEvento = evento.event_type;

    console.log('Evento de PayPal recibido:', tipoEvento);

    if (tipoEvento === 'BILLING.SUBSCRIPTION.ACTIVATED') {
      const correo = evento.resource.subscriber.email_address;
      const idPlanPayPal = evento.resource.plan_id;

      // Por defecto Pro (emprendedor) — Básico ya no existe como plan vendible
      let planNova = 'emprendedor';
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
      `SELECT mensajes_usados, limite_mensajes, documentos_usados, limite_documentos, es_admin,
              resumen_memoria, datos_fijados, historial_reciente, contador_intercambios,
              nombre, conversacion_activa
       FROM usuarios WHERE correo = $1`,
      [req.correoUsuario]
    );
    const usuario = resultado.rows[0];
    const esAdmin = usuario.es_admin === true;

    if (!esAdmin && usuario.limite_documentos === 0) {
      return res.status(403).json({ error: 'Tu plan no incluye subir documentos o fotos. Mejora tu plan para desbloquear esta función.' });
    }

    if (!esAdmin && usuario.mensajes_usados >= usuario.limite_mensajes) {
      return res.status(403).json({ error: 'Alcanzaste el límite de tu plan este mes.' });
    }

    if (!esAdmin && usuario.documentos_usados >= usuario.limite_documentos) {
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

    const historialReciente = usuario.historial_reciente || [];

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-5',
      max_tokens: 700,
      system: construirSystemConMemoria(usuario.resumen_memoria, usuario.datos_fijados, usuario.nombre),
      messages: construirMensajesConHistorial(historialReciente, [bloqueArchivo, { type: 'text', text: mensajeTexto }]),
    });

    await pool.query(
      `UPDATE usuarios SET mensajes_usados = mensajes_usados + 1, documentos_usados = documentos_usados + 1 WHERE correo = $1`,
      [req.correoUsuario]
    );

    const textoRespuesta = response.content
      .filter(bloque => bloque.type === 'text')
      .map(bloque => bloque.text)
      .join('\n\n');

    const nombreArchivo = esImagen ? 'una imagen' : 'un documento PDF';
    actualizarMemoriaTrasIntercambio(
      req.correoUsuario,
      `[Subió ${nombreArchivo}] ${mensajeTexto}`,
      textoRespuesta,
      usuario.resumen_memoria,
      historialReciente,
      usuario.contador_intercambios || 0
    ).catch(error => console.error('Error actualizando memoria:', error));

    guardarEnConversacion(req.correoUsuario, usuario.conversacion_activa, `[Subió ${nombreArchivo}] ${mensajeTexto}`, textoRespuesta)
      .catch(error => console.error('Error guardando en conversación:', error));

    res.status(200).json({
      status: 'success',
      respuesta: textoRespuesta,
      documentosUsados: usuario.documentos_usados + 1,
      limiteDocumentos: usuario.limite_documentos
    });
  } catch (error) {
    console.error('Error procesando archivo:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// ============================================
// MI CUENTA + HISTORIAL DE CHATS (Tanda 3, 20 sept 2026)
// ============================================

// Datos de la pantalla "Mi cuenta": nombre, plan, uso del mes y fechas
app.get('/api/mi-cuenta', verificarSesion, async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT nombre, correo, plan, fecha_pago, creado_en,
              mensajes_usados, limite_mensajes, busquedas_usadas, limite_busquedas,
              documentos_usados, limite_documentos, es_admin
       FROM usuarios WHERE correo = $1`,
      [req.correoUsuario]
    );
    const u = resultado.rows[0];
    const NOMBRES_PLAN_CUENTA = { emprendedor: 'Nova Pro', negocios: 'Nova Plus', basico: 'Nova Básico', prueba: 'Prueba gratis', ninguno: 'Sin plan activo' };
    res.status(200).json({
      status: 'success',
      nombre: u.nombre || '',
      correo: u.correo,
      plan: NOMBRES_PLAN_CUENTA[u.plan] || u.plan,
      fechaPago: u.fecha_pago,
      miembroDesde: u.creado_en,
      esAdmin: u.es_admin === true,
      uso: {
        mensajesUsados: u.mensajes_usados,
        limiteMensajes: u.limite_mensajes,
        busquedasUsadas: u.busquedas_usadas,
        limiteBusquedas: u.limite_busquedas,
        documentosUsados: u.documentos_usados,
        limiteDocumentos: u.limite_documentos
      }
    });
  } catch (error) {
    console.error('Error obteniendo Mi cuenta:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Guardar o cambiar el nombre del cliente (opcional; vacío = borrarlo)
app.post('/api/mi-cuenta/nombre', verificarSesion, async (req, res) => {
  try {
    const nombre = String(req.body.nombre || '').replace(/\s+/g, ' ').trim().slice(0, 60);
    await pool.query(`UPDATE usuarios SET nombre = $1 WHERE correo = $2`, [nombre, req.correoUsuario]);
    res.status(200).json({ status: 'success', nombre: nombre });
  } catch (error) {
    console.error('Error guardando nombre:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Lista de chats del usuario, del más reciente al más viejo (panel de las tres rayitas)
app.get('/api/conversaciones', verificarSesion, async (req, res) => {
  try {
    const resultado = await pool.query(
      `SELECT id, titulo, actualizado_en FROM conversaciones
       WHERE correo = $1 ORDER BY actualizado_en DESC LIMIT 50`,
      [req.correoUsuario]
    );
    res.status(200).json({ status: 'success', conversaciones: resultado.rows });
  } catch (error) {
    console.error('Error listando conversaciones:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Reabrir un chat anterior: se pinta completo en pantalla, se vuelve la conversación
// activa, y Nova recupera los últimos 10 intercambios de ese hilo como contexto vivo
// (la memoria de largo plazo y "recuérdame esto" no se tocan)
app.post('/api/abrir-chat', verificarSesion, async (req, res) => {
  try {
    const id = parseInt(req.body.id, 10);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: 'Falta el chat que quieres abrir.' });
    }

    const resultado = await pool.query(
      `SELECT id, titulo, mensajes FROM conversaciones WHERE id = $1 AND correo = $2`,
      [id, req.correoUsuario]
    );
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Ese chat no existe.' });
    }
    const conversacion = resultado.rows[0];
    const mensajes = conversacion.mensajes || [];

    // Se rearman los pares usuario→Nova y se toman los últimos 10 como hilo vivo
    const intercambios = [];
    for (let i = 0; i + 1 < mensajes.length; i += 2) {
      if (mensajes[i].rol === 'usuario' && mensajes[i + 1].rol === 'nova') {
        intercambios.push({ usuario: mensajes[i].texto, nova: mensajes[i + 1].texto });
      }
    }
    const ultimosIntercambios = intercambios.slice(-6);

    await pool.query(
      `UPDATE usuarios SET conversacion_activa = $1, historial_reciente = $2, contador_intercambios = 0 WHERE correo = $3`,
      [conversacion.id, JSON.stringify(ultimosIntercambios), req.correoUsuario]
    );

    res.status(200).json({
      status: 'success',
      id: conversacion.id,
      titulo: conversacion.titulo,
      mensajes: mensajes
    });
  } catch (error) {
    console.error('Error abriendo chat:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Borrar un chat del historial; si era el que estaba abierto, el hilo vivo también se reinicia
app.post('/api/borrar-chat', verificarSesion, async (req, res) => {
  try {
    const id = parseInt(req.body.id, 10);
    if (!Number.isInteger(id)) {
      return res.status(400).json({ error: 'Falta el chat que quieres borrar.' });
    }

    const resultado = await pool.query(
      `DELETE FROM conversaciones WHERE id = $1 AND correo = $2 RETURNING id`,
      [id, req.correoUsuario]
    );
    if (resultado.rows.length === 0) {
      return res.status(404).json({ error: 'Ese chat no existe.' });
    }

    await pool.query(
      `UPDATE usuarios SET conversacion_activa = NULL, historial_reciente = '[]'::jsonb, contador_intercambios = 0
       WHERE correo = $1 AND conversacion_activa = $2`,
      [req.correoUsuario, id]
    );

    res.status(200).json({ status: 'success', mensaje: 'Chat eliminado.' });
  } catch (error) {
    console.error('Error borrando chat:', error);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// Sentry: atrapa cualquier error no manejado y te avisa por correo antes de responder al cliente
Sentry.setupExpressErrorHandler(app);
app.use((err, req, res, next) => {
  console.error('Error no manejado:', err);
  res.status(500).json({ error: 'Error interno del servidor.' });
});

app.listen(PORT, () => {
  console.log(`Servidor de Nova corriendo en el puerto ${PORT}`);
});
