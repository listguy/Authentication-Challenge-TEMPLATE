/* write your server code here */
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");

app.use(express.json());

const USERS = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "hashed Rc123456!",
    isAdmin: true,
  },
];

const INFORMATION = [
  // Example object
  // {
  //     name: "nitzan",
  //     info: "Da Man"
  // }
];

app.post("/users/register", async (req, res) => {
  const { body } = req;

  try {
    if (USERS.find((user) => user.email === body.email))
      // if user already exists, throw an error
      throw new Error("user exists");

    const salt = bcrypt.genSalt(); //generate salt, can also write 10 in hash function and it will auto generate salt
    const hashedpwd = bcrypt.hash(body.password, salt); //hash the password and add salt

    USERS.push({
      email: body.email,
      name: body.user,
      password: hashedpwd, //Hash password
      isAdmin: false,
    });

    INFORMATION.push({ name: body.user, info: `${body.user} info` });

    res.status(210).send("Register Success");
  } catch (e) {
    res.status(409).send("user already exists");
  }
});

app.post("/users/login", (req, res) => {
  const { body } = req;

  const user = USERS.find((user) => user.email === body.email);
  //Check user exists
  if (user === null) res.status(404).send("cannot find user");

  //compare passwords
  try {
    if (bcrypt.compare(req.body.password, user.password))
      res.status(200).send("login");
    else {
      res.status(403).send("User or Password incorrect");
    }
  } catch (e) {
    res.send(500);
  }
});
module.exports = app;
