require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken')

const app = express();
app.use(express.json());

// Best practice: store in database or reddis cache, this is demo only
let refreshTokens = []

app.post('/token', (req, res) => {
  const refreshToken = req.body.token

  if (refreshTokens == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  })
})

app.delete('/logout', (req, res) => {
  // normally token would be in a DB or something and this would be deleted
  // we are simply deleting the refreshTokens array
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  res.sendStatus(204);
})

app.post('/login', (req, res) => {
  // Authenticate User - create separate login functionality

  const username = req.body.username;
  const user = { name: username }

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokens.push(refreshToken);
  res.json({ accessToken: accessToken, refreshToken: refreshToken })

});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '20s' });
  // jwt will only be valid for 15secs, then expire
  // in production, this would be valid for a lot longer, maybe 15-30mins
}

app.listen(4000);