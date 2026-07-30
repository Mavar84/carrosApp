const mongoose = require('mongoose');
const dotenv = require('dotenv');

dotenv.config();

const uri = process.env.MONGO;

let conexionPromise;

async function conectarBD() {
  if (!uri) {
    throw new Error('La variable de entorno MONGO no esta configurada');
  }

  if (mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  if (!conexionPromise) {
    conexionPromise = mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000,
    });
  }

  try {
    await conexionPromise;
    return mongoose.connection;
  } catch (error) {
    conexionPromise = null;
    throw error;
  }
}

module.exports = conectarBD;
