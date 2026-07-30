const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const conectarBD = require('./conexion');
const Usuario = require('./usuario_esquema');
const AutoClasico = require('./autoClasicoEsquema');

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(async (_req, _res, next) => {
  try {
    await conectarBD();
    next();
  } catch (error) {
    next(error);
  }
});

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.SECRETO);
    req.usuarioId = decoded.id;
    next();
  } catch (_error) {
    return res.status(403).json({ error: 'Token invalido o expirado' });
  }
}

function normalizarAuto(body) {
  return {
    marca: body.marca,
    modelo: body.modelo,
    anio: body.anio ? Number(body.anio) : undefined,
    paisOrigen: body.paisOrigen,
    tipoCarroceria: body.tipoCarroceria,
    estadoConservacion: body.estadoConservacion,
    motor: body.motor,
    color: body.color,
    valorEstimado: body.valorEstimado ? Number(body.valorEstimado) : undefined,
    imagenUrl: body.imagenUrl || 'sin imagen',
  };
}

app.post('/api/verificatoken', verificarToken, (_req, res) => {
  res.json({ mensaje: 'verificado' });
});

app.post('/api/registro', async (req, res) => {
  try {
    const { nombre, correo, clave } = req.body;

    if (!nombre || !correo || !clave) {
      return res.status(400).json({ error: 'Nombre, correo y clave son obligatorios' });
    }

    const existente = await Usuario.findOne({ correo });
    if (existente) {
      return res.status(409).json({ error: 'El correo ya esta registrado' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(clave, salt);
    const nuevoUsuario = new Usuario({ nombre, correo, clave: hash });

    await nuevoUsuario.save();

    res.status(201).json({
      mensaje: 'Usuario registrado con exito',
      id: nuevoUsuario._id,
    });
  } catch (error) {
    res.status(400).json({ error: error.message || 'No se pudo registrar el usuario' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { correo, clave } = req.body;
    const usuario = await Usuario.findOne({ correo });

    if (!usuario) {
      return res.status(401).json({ error: 'Credenciales invalidas' });
    }

    const passwordOk = await bcrypt.compare(clave, usuario.clave);
    if (!passwordOk) {
      return res.status(401).json({ error: 'Credenciales invalidas' });
    }

    const token = jwt.sign({ id: usuario._id }, process.env.SECRETO, { expiresIn: '1h' });
    res.json({ token });
  } catch (_error) {
    res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.get('/api/usuarios', async (_req, res) => {
  try {
    const usuarios = await Usuario.find().select('-clave');
    res.json(usuarios);
  } catch (_error) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/api/usuarios/:id', async (req, res) => {
  try {
    const usuario = await Usuario.findById(req.params.id).select('-clave');
    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(usuario);
  } catch (_error) {
    res.status(400).json({ error: 'Identificador de usuario invalido' });
  }
});

app.put('/api/usuarios/:id', async (req, res) => {
  try {
    const usuarioActualizado = await Usuario.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true,
    }).select('-clave');

    if (!usuarioActualizado) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(usuarioActualizado);
  } catch (_error) {
    res.status(400).json({ error: 'Error al actualizar usuario' });
  }
});

app.delete('/api/usuarios/:id', async (req, res) => {
  try {
    const usuarioEliminado = await Usuario.findByIdAndDelete(req.params.id);
    if (!usuarioEliminado) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ message: 'Usuario eliminado' });
  } catch (_error) {
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.get('/api/usuario-logueado', verificarToken, async (req, res) => {
  try {
    const usuario = await Usuario.findById(req.usuarioId).select('-clave');
    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(usuario);
  } catch (_error) {
    res.status(500).json({ error: 'Error al obtener los datos del usuario' });
  }
});

app.post('/api/auto', verificarToken, async (req, res) => {
  try {
    const nuevoAuto = new AutoClasico(normalizarAuto(req.body));
    const autoGuardado = await nuevoAuto.save();
    res.status(201).json(autoGuardado);
  } catch (_error) {
    res.status(400).json({ error: 'Error al registrar el auto clasico' });
  }
});

app.get('/api/auto', verificarToken, async (_req, res) => {
  try {
    const autos = await AutoClasico.find().sort({ _id: -1 });
    res.json(autos);
  } catch (_error) {
    res.status(500).json({ error: 'Error al obtener los autos' });
  }
});

app.get('/api/auto/:id', verificarToken, async (req, res) => {
  try {
    const auto = await AutoClasico.findById(req.params.id);

    if (!auto) {
      return res.status(404).json({ error: 'Auto no encontrado' });
    }

    res.json(auto);
  } catch (_error) {
    res.status(400).json({ error: 'Identificador de auto invalido' });
  }
});

app.put('/api/auto/:id', verificarToken, async (req, res) => {
  try {
    const autoActualizado = await AutoClasico.findByIdAndUpdate(
      req.params.id,
      normalizarAuto(req.body),
      { new: true, runValidators: true }
    );

    if (!autoActualizado) {
      return res.status(404).json({ error: 'Auto no encontrado' });
    }

    res.json(autoActualizado);
  } catch (_error) {
    res.status(400).json({ error: 'Error al actualizar el auto' });
  }
});

app.delete('/api/auto/:id', verificarToken, async (req, res) => {
  try {
    const autoEliminado = await AutoClasico.findByIdAndDelete(req.params.id);

    if (!autoEliminado) {
      return res.status(404).json({ error: 'Auto no encontrado' });
    }

    res.json({ mensaje: 'Auto eliminado correctamente' });
  } catch (_error) {
    res.status(400).json({ error: 'Error al eliminar el auto' });
  }
});

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(500).json({ error: 'Error interno del servidor' });
});

module.exports = app;
