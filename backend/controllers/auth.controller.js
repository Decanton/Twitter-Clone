import bcrypt from 'bcrypt';
import User from '../models/user.model.js';
import { generateTokenandSetCookie } from '../lib/utils/generateToken.js';

export const signup = async (req, res) => {
  try {
    const { username, fullName, password, email } = req.body;

    if (!username || !fullName || !password || !email) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const existingUserEmail = await User.findOne({ email });
    if (existingUserEmail) {
      return res.status(400).json({ error: 'Email already exists' });
    }
	if (password.length < 6) {
		return res.status(400).json({ error: 'Password must be at least 6 characters long' });
	}
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      fullName,
      username,
      email,
      password: hashedPassword
    });

    await newUser.save();
    generateTokenandSetCookie(newUser._id, res);

    res.status(201).json({
      _id: newUser._id,
      fullName: newUser.fullName,
      username: newUser.username,
      email: newUser.email,
      followers: newUser.followers,
      following: newUser.following,
      profileImg: newUser.profileImg,
    });
  } catch (error) {
    console.error('Error in Signup Controller:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};

export const login = async (req, res) => {
  try {
	console.log('Received body:', req.body);
    const { usernameOrEmail, password } = req.body;

    if (!usernameOrEmail || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    const user = await User.findOne({
      $or: [{ username: usernameOrEmail }, { email: usernameOrEmail }]
    });

    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const isPasswordMatch = await bcrypt.compare(password, user?.password || '');
    if (!isPasswordMatch) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    generateTokenandSetCookie(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      followers: user.followers,
      following: user.following,
      profileImg: user.profileImg,
    });
  } catch (error) {
    console.error('Error in Login Controller:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};

export const logout = async (req, res) => {
  try {
    res.cookie('jwt', '', {
      httpOnly: true,
      expires: new Date(0),
    });
    res.status(200).json({ message: 'Successfully logged out' });
  } catch (error) {
    console.error('Error in Logout Controller:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};
export const getMe = async (req, res) => {
  try {
	const user = await User.findById(req.user._id)
	.select('-password');
	res.status(200).json(user);
  } catch (error) {
	console.error('Error in getMe Controller:', error.message);
	res.status(500).json({ error: 'Server error' });
  }
};


