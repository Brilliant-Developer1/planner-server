require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const app = express();
const { MongoClient, ObjectId } = require('mongodb');
const cors = require("cors");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');

const port = process.env.PORT || 3001;
const uri = process.env.MONGO_URI;
const secret = process.env.JWT_SECRET;

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});

app.use(cors({
  origin: ["http://localhost:3000"], // Add your allowed origins
  methods: ["POST", "GET", "PATCH", "DELETE"],
  credentials: true,
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
app.use(express.json());

function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).send("Token not provided");
  }

  try {
    const verify = jwt.verify(token, secret);
    if (!verify?.email) {
      return res.status(401).send("You are not authorized");
    }
    req.user = verify.email;
    next();
  } catch (error) {
    console.error("Error verifying token:", error);
    return res.status(401).send("Invalid token");
  }
}

const client = new MongoClient(uri, {
  tls: true,
  tlsAllowInvalidCertificates: true,
  tlsAllowInvalidHostnames: true,
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB!");
    const database = client.db('myDatabase');
    const usersCollection = database.collection('users');
    const tasksCollection = database.collection('tasks');

    // Task Routes
    app.post('/tasks', verifyToken, async (req, res) => {
      const { title, description, deadline, priority, status } = req.body;
      const email = req.user; // Extracted from the token by verifyToken middleware
      const newTask = { title, description, deadline, priority, status, email };
      try {
        const result = await tasksCollection.insertOne(newTask);
        const insertedTask = await tasksCollection.findOne({ _id: result.insertedId }); // Fetch the inserted task
        res.status(201).send(insertedTask); // Return the inserted document
      } catch (error) {
        console.error('Error inserting task:', error); // Log the error
        res.status(500).send({ message: 'Error inserting task', error });
      }
    });

    app.get('/tasks', verifyToken, async (req, res) => {
      const email = req.user; // Extracted from the token by verifyToken middleware
      try {
        const tasks = await tasksCollection.find({ email }).toArray();
        res.status(200).send(tasks);
      } catch (error) {
        console.error('Error fetching tasks:', error); // Log the error
        res.status(500).send({ message: 'Error fetching tasks', error });
      }
    });

     // PATCH route to update task status
     app.patch('/tasks/:id/status', verifyToken, async (req, res) => {
      const taskId = req.params.id;
      const { status } = req.body;
      try {
        const result = await tasksCollection.updateOne(
          { _id: new ObjectId(taskId), email: req.user },
          { $set: { status } }
        );
        if (result.modifiedCount === 0) {
          return res.status(404).send({ message: 'Task not found or no changes made' });
        }
        res.status(200).send({ message: 'Task status updated successfully' });
      } catch (error) {
        console.error('Error updating task status:', error); // Log the error
        res.status(500).send({ message: 'Error updating task status', error });
      }
    });

    // Update task
    app.patch('/tasks/:id', verifyToken, async (req, res) => {
      const taskId = req.params.id;
      const { title, description, deadline, priority, status } = req.body;
      try {
        const result = await tasksCollection.updateOne(
          { _id: new ObjectId(taskId), email: req.user },
          { $set: { title, description, deadline, priority, status } }
        );
        if (result.modifiedCount === 0) {
          return res.status(404).send({ message: 'Task not found or no changes made' });
        }
        const updatedTask = await tasksCollection.findOne({ _id: new ObjectId(taskId) });
        res.status(200).send(updatedTask);
      } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).send({ message: 'Error updating task', error });
      }
    });

    // DELETE route
    app.delete('/tasks/:id', verifyToken, async (req, res) => {
      const taskId = req.params.id;
      try {
        const result = await tasksCollection.deleteOne({ _id: new ObjectId(taskId), email: req.user });
        if (result.deletedCount === 0) {
          return res.status(404).send({ message: 'Task not found' });
        }
        res.status(200).send({ message: 'Task deleted successfully' });
      } catch (error) {
        console.error('Error deleting task:', error); // Log the error
        res.status(500).send({ message: 'Error deleting task', error });
      }
    });

    // User Routes
    app.post('/users', async (req, res) => {
      try {
        const { name, email, password } = req.body;

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = { name, email, password: hashedPassword };
        const result = await usersCollection.insertOne(newUser);

        // Generate JWT
        const token = jwt.sign({ userId: result.insertedId, email }, secret, { expiresIn: '1h' });
        res.status(201).send({ token });
      } catch (error) {
        res.status(500).send({ message: 'Error inserting user', error });
      }
    });

    app.get('/users', async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        res.status(200).send(users);
      } catch (error) {
        res.status(500).send({ message: 'Error fetching users', error });
      }
    });

    app.get('/users/:id', async (req, res) => {
      const id = req.params.id;
      try {
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });
        if (!user) {
          return res.status(404).send("User not found");
        }
        res.send(user);
      } catch (error) {
        console.error("Error retrieving user:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.patch('/users/:id', async (req, res) => {
      const id = req.params.id;
      const updatedData = req.body;
      try {
        const result = await usersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updatedData }
        );
        res.send(result);
      } catch (error) {
        console.error("Error updating user:", error);
        res.status(500).send("Internal Server Error");
      }
    });

    app.post('/login', async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });

        if (!user) {
          return res.status(401).send({ message: 'Invalid email or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).send({ message: 'Invalid email or password' });
        }

        // Generate JWT
        const token = jwt.sign({ userId: user._id, email }, secret, { expiresIn: '1h' });
        res.status(200).send({ token });
      } catch (error) {
        res.status(500).send({ message: 'Error logging in', error });
      }
    });

    // Auth route to verify Firebase token and return JWT
    app.post('/auth', async (req, res) => {
      const { token } = req.body;
      try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        const email = decodedToken.email;

        // Check if user exists in the database
        let user = await usersCollection.findOne({ email });
        if (!user) {
          user = await usersCollection.insertOne({ email });
        }

        // Generate JWT
        const jwtToken = jwt.sign({ userId: user._id, email }, secret, { expiresIn: '1h' });
        res.status(200).send({ token: jwtToken });
      } catch (error) {
        res.status(500).send({ message: 'Error verifying token', error });
      }
    });

  } finally {
    // Optionally close the MongoDB connection here if needed
  }
}

run().catch(console.log);

app.get('/', (req, res) => {
  res.json('Route is working');
});

app.listen(port, (req, res) => {
  console.log('App is running on:', port);
});
