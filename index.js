const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Joi, celebrate, errors } = require('celebrate');
 require('dotenv').config();
const port = process.env.PORT || 5000


const app = express();

// Configure JSON body parser
app.use(express.json());

// Configure MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/blog', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Define MongoDB models
const User = mongoose.model('User', new mongoose.Schema({
  username: String,
  password: String,
}));

const Post = mongoose.model('Post', new mongoose.Schema({
  title: String,
  content: String,
  userId: String,
}));

// JWT secret key
const JWT_SECRET = 'your-secret-key';

// Middleware for JWT authentication
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({ message: 'Missing authorization token' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid authorization token' });
    }

    req.user = user;
    next();
  });
};

// Routes

app.post('/api/auth/register', celebrate({
  body: Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
  }),
}), async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({ username, password: hashedPassword });
    await user.save();

    return res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});
 // login
app.post('/api/auth/login', celebrate({
  body: Joi.object({
    username: Joi.string().required(),
    password: Joi.string().required(),
  }),
}), async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Validate the password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET);

    return res.json({ token });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/posts', authenticateJWT, async (req, res) => {
  try {
    // Retrieve all blog posts
    const posts = await Post.find();

    return res.json(posts);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/posts', celebrate({
  body: Joi.object({
    title: Joi.string().required(),
    content: Joi.string().required(),
  }),
}), authenticateJWT, async (req, res) => {
  try {
    const { title, content } = req.body;

    // Create a new post associated with the authenticated user
    const post = new Post({ title, content, userId: req.user.userId });
    await post.save();

    return res.json(post);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/posts/:id', authenticateJWT, async (req, res) => {
  try {
    const postId = req.params.id;

    // Find the blog post by ID
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    return res.json(post);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/posts/:id', celebrate({
  body: Joi.object({
    title: Joi.string(),
    content: Joi.string(),
  }),
}), authenticateJWT, async (req, res) => {
  try {
    const postId = req.params.id;
    const { title, content } = req.body;

    // Find the blog post by ID and ensure it belongs to the authenticated user
    const post = await Post.findOneAndUpdate(
      { _id: postId, userId: req.user.userId },
      { title, content },
      { new: true }
    );

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    return res.json(post);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/api/posts/:id', authenticateJWT, async (req, res) => {
  try {
    const postId = req.params.id;

    // Find the blog post by ID and ensure it belongs to the authenticated user
    const post = await Post.findOneAndDelete({
      _id: postId,
      userId: req.user.userId,
    });

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    return res.json({ message: 'Post deleted successfully' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/users', authenticateJWT, async (req, res) => {
  try {
    // Retrieve all user profiles
    const users = await User.find();

    return res.json(users);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/users/:id', authenticateJWT, async (req, res) => {
  try {
    const userId = req.params.id;

    // Find the user profile by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/api/users/:id', celebrate({
  body: Joi.object({
    username: Joi.string(),
    email: Joi.string().email(),
  }),
}), authenticateJWT, async (req, res) => {
  try {
    const userId = req.params.id;
    const { username, email } = req.body;

    // Find the user profile by ID and ensure it belongs to the authenticated user
    const user = await User.findOneAndUpdate(
      { _id: userId, _id: req.user.userId },
      { username, email },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    return res.json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Handle Celebrate validation errors
app.use(errors());


app.listen(port, () => {
   console.log('DB connected successfully');
  console.log(`Server started on port: ${port}`);
});