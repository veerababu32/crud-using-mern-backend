const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/user");

async function signup(req, res) {
  try {
    // Get the email & pass off req body
    const { username, email, password } = req.body;

    // Hash password
    var hashedPassword = bcrypt.hashSync(password, 8);

    // Create a user with the data
    await User.create({ username, email, password: hashedPassword });

    // respond
    res.sendStatus(200);
  } catch (err) {
    console.log(err);
    res.sendStatus(400);
  }
}

async function login(req, res) {
  try {
    // Get the email & pass off req body
    const { email, password } = req.body;

    // find the user with requested email
    const user = await User.findOne({ email });
    if (!user) return res.sendStatus(401);

    // compare the sent in pass with hash pass
    const passwordMatch = bcrypt.compareSync(password, user.password);
    if (!passwordMatch) return res.sendStatus(401);

    // create a jwt token
    const exp = Date.now() + 1000 * 60 * 60 * 24 * 30;
    const token = jwt.sign({ sub: user._id, exp }, process.env.SECRET_KEY);

    // Set the cookie
    res.cookie("Authorization", token, {
      expires: new Date(exp),
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });

    // send it
    res.sendStatus(200);
  } catch (err) {
    console.log(err);
    res.sendStatus(400);
  }
}

function logout(req, res) {
  try {
    res.clearCookie("Authorization");
    res.sendStatus(200);
  } catch (err) {
    console.log(err);
    res.sendStatus(400);
  }
}

function checkAuth(req, res) {
  try {
    // console.log(req.user);
    res.sendStatus(200);
  } catch (err) {
    console.log(err);
    res.sendStatus(400);
  }
}

module.exports = {
  signup,
  login,
  logout,
  checkAuth,
};
