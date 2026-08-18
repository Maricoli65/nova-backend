// Backend de Nova - Clenova Digital Studio
// Este servidor recibe los mensajes del cliente y los envía a Claude

const express = require('express');
const cors = require('cors');
const Anthropic = require('@anthropic-ai/sdk');

const app = express();
app.use(cors());
app.use(express.json());

// La clave API se guarda como variable de entorno en Railway (NUNCA aquí directo)
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

// Ruta principal: recibe el mensaje del usuario y responde con Claude
app.post('/chat', async (req, res) => {
  try {
    const userMessage = req.body.message;

    if (!userMessage) {
      return res.status(400).json({ error: 'Falta el mensaje' });
    }

    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 1024,
      messages: [{ role: 'user', content: userMessage }],
    });

    res.json({ reply: response.content[0].text });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Algo salió mal, intenta de nuevo' });
  }
});

// Ruta simple para confirmar que el servidor está vivo
app.get('/', (req, res) => {
  res.send('Nova backend funcionando correctamente ✅');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor de Nova corriendo en el puerto ${PORT}`);
});
