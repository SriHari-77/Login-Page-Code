const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');

const app = express();
const port = 5000;

app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root', // Replace with your MySQL username
  password: '', // Replace with your MySQL password (empty if none)
  database: 'signup', // Updated database name to 'signup'
});

db.connect((err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to MySQL database');
  }
});

// Signup endpoint
app.post('/signup', async (req, res) => {
  const { email, firstName, lastName, password } = req.body;

  // Validate email, firstName, lastName, and password (add your validation logic here)
  if (!email || !firstName || !lastName || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    // Check if the email already exists
    const emailExists = await checkEmailExists(email);

    if (emailExists) {
      return res.status(400).json({ error: 'Email is already taken' });
    }

    // Hash the password
    bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
      if (hashErr) {
        console.error('Hashing error:', hashErr);
        return res.status(500).json({ error: 'Internal server error' });
      }

      // Insert user into the database
      db.query(
        'INSERT INTO users (email, first_name, last_name, password) VALUES (?, ?, ?, ?)',
        [email, firstName, lastName, hashedPassword],
        (insertErr, result) => {
          if (insertErr) {
            console.error('Database insert error:', insertErr);
            return res.status(500).json({ error: 'Internal server error' });
          }

          // Generate JWT token for the new user
          const token = jwt.sign({ userId: result.insertId }, 'your_secret_key', { expiresIn: '1h' });

          res.json({ token });
        }
      );
    });
  } catch (error) {
    console.error('Signup Error:', error.response?.data?.error || 'Internal server error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate email and password
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Check if the email exists
    const user = await getUserByEmail(email);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the provided password with the hashed password in the database
    bcrypt.compare(password, user.password, (compareErr, passwordMatch) => {
      if (compareErr) {
        console.error('Password comparison error:', compareErr);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Generate JWT token for the authenticated user
      const token = jwt.sign({ userId: user.id }, 'your_secret_key', { expiresIn: '1h' });

      res.json({ token });
    });
  } catch (error) {
    console.error('Login Error:', error.response?.data?.error || 'Internal server error');
    res.status(500).json({ error: 'Internal server error' });
  }
});

const checkEmailExists = async (emailToCheck) => {
  return new Promise((resolve, reject) => {
    db.query('SELECT COUNT(*) as count FROM users WHERE email = ?', [emailToCheck], (queryErr, results) => {
      if (queryErr) {
        reject(queryErr);
      } else {
        resolve(results[0].count > 0);
      }
    });
  });
};

const getUserByEmail = (email) => {
  return new Promise((resolve, reject) => {
    db.query('SELECT * FROM users WHERE email = ?', [email], (queryErr, results) => {
      if (queryErr) {
        reject(queryErr);
      } else {
        resolve(results[0] || null);
      }
    });
  });
};

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
