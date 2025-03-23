// server.js

// Import required modules
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

// Initialize Express app
const app = express();

// Define the port from environment variables or default to 5000
const PORT = process.env.PORT || 5000;

// Middleware Setup
app.use(cors()); // Enable CORS
app.use(bodyParser.json()); // Parse JSON request bodies

// Basic Route
app.get('/', (req, res) => {
  res.send('SpyderCare Backend is running');
});

// Example API Endpoint
app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello from the backend!' });
});

/* 
  ------------
   DUMMY DATA
  ------------
  For demonstration only. 
  In production, store user data in a real database.
*/
const users = [];

/* 
  --------------
   REGISTER API
  --------------
*/
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  // Check if user already exists
  const existingUser = users.find((u) => u.username === username);
  if (existingUser) {
    return res.status(400).json({ message: 'Username is already taken.' });
  }

  // Create a new user (In a real app, hash the password!)
  const newUser = { username, password };
  users.push(newUser);

  // Send back success response
  res.status(201).json({ message: 'User registered successfully!' });
});

/* 
  -----------
   LOGIN API
  -----------
*/
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  // Find the user
  const user = users.find((u) => u.username === username);

  // If user doesn’t exist or password doesn’t match
  if (!user || user.password !== password) {
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  // If credentials are valid, return a token or success message
  // In a real app, you’d create a JWT or session to keep track of the user
  res.status(200).json({ message: 'Login successful!', user: { username } });
});

// Export the app for Vercel (remove app.listen)
module.exports = app;