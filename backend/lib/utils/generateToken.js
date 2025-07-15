import jwt from 'jsonwebtoken';

export const generateTokenandSetCookie = (userid, res) => {
  const token = jwt.sign({ userId: userid }, process.env.JWT_SECRET, {
    expiresIn: '15d',
  });

  res.cookie('jwt', token, {
    maxAge: 15 * 24 * 60 * 60 * 1000, // 15 days
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV !== 'development',
  });
};
