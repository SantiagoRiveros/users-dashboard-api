const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = 3001;
const JWT_SECRET = "your_secret_key";

app.use(cors());

app.use(express.json());

// Middleware para parsear JSON
app.use(bodyParser.json());

// Función para cargar datos desde el archivo JSON
const loadData = () => {
  const data = fs.readFileSync("data/users.json");
  return JSON.parse(data);
};

// Función para guardar usuarios en el JSON
const saveUsers = (users) => {
  const roles = loadData().roles;
  const data = JSON.stringify({ users, roles }, null, 2);
  fs.writeFileSync("data/users.json", data);
};

// RUTA DE REGISTRO
app.post("/register", async (req, res) => {
  const { username, nombre, rol, password } = req.body;

  if (!username || !nombre || !rol || !password) {
    return res.status(400).json({ message: "Faltan datos obligatorios" });
  }

  const data = loadData();
  const users = data.users;
  const existingUser = users.find((user) => user.username === username);

  if (existingUser) {
    return res.status(400).json({ message: "El usuario ya existe" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: users.length + 1,
    username,
    nombre,
    rol,
    password: hashedPassword,
  };

  users.push(newUser);
  saveUsers(users);

  res.status(201).json({ message: "Usuario registrado correctamente" });
});

// RUTA DE LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);
  if (!username || !password) {
    return res.status(400).json({ message: "Faltan datos obligatorios" });
  }

  const data = loadData();
  const user = data.users.find((user) => user.username === username);

  if (!user) {
    return res.status(400).json({ message: "Usuario no encontrado" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({ message: "Contraseña incorrecta" });
  }

  const token = jwt.sign({ id: user.id, rol: user.rol }, JWT_SECRET, {
    expiresIn: "1h",
  });
  res.json({ message: "Login exitoso", token });
});

// RUTA PROTEGIDA (EJEMPLO)
app.get("/protected", (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Token no proporcionado" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token inválido" });
    }

    res.json({ message: "Acceso a ruta protegida", user });
  });
});

// NUEVA RUTA: Obtener todos los usuarios
app.get("/users", (req, res) => {
  const data = loadData();
  res.json(data.users);
});

// NUEVA RUTA: Obtener todos los roles
app.get("/roles", (req, res) => {
  const data = loadData();
  res.json(data.roles);
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
