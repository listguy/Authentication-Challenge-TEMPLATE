/* write your server code here */
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const AT_SECRET = "vkldsnvjdsvdsjk";
const RT_SECRET = "vsv834t4nfrejfe";

app.use(express.json());

const USERS = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "$2b$10$aGzI73x0NjcPLXDGzezYJuhqTklp0dL6cLjJcOV34/oky5KUjSkaS",
    isAdmin: true,
  },
];

const INFORMATION = [{ name: "admin", info: "admin info" }];

//this will store the refresh tokens for us
let REFRESH_TOKENS = [];

app.post("/users/register", async (req, res) => {
  const { body } = req;

  try {
    if (USERS.find((user) => user.email === body.email))
      // if user already exists, throw an error
      throw new Error("user exists");

    const salt = await bcrypt.genSalt(10); //generate salt, can also write 10 in hash function and it will auto generate salt
    const hashedpwd = await bcrypt.hash(body.password, salt); //hash the password and add salt

    USERS.push({
      email: body.email,
      name: body.name,
      password: hashedpwd, //Hash password
      isAdmin: false,
    });

    INFORMATION.push({
      name: body.name,
      info: `${body.name} info`,
      email: body.email,
    });

    res.status(201).send("Register Success");
  } catch (e) {
    res.status(409).send("user already exists");
  }
});

app.post("/users/login", async (req, res) => {
  const { body } = req;

  const user = USERS.find((user) => user.email === body.email);

  //Check user exists
  if (!user) return res.status(404).send("cannot find user");

  //compare passwords
  if (await bcrypt.compare(body.password, user.password)) {
    //create access token with user info
    const accessToken = createAccessToken(user);
    //create refresh token, no expiration date
    const refreshToken = jwt.sign(user, RT_SECRET);
    //add refreshTOken to DB
    REFRESH_TOKENS.push(refreshToken);

    //send success response to user
    res.status(200).json({
      accessToken: accessToken,
      refreshToken: refreshToken,
      name: user.name,
      isAdmin: user.isAdmin,
    });
  } else {
    res.status(403).send("User or Password incorrect");
  }
});

//validate the token
app.post("/users/tokenValidate", (req, res) => {
  const authHeader = req.headers["authorization"]; //get auth header from rewuset
  const token = authHeader && authHeader.slice(7); //remove 'bearer ' start

  if (!token) return res.status(401).send("Access Token Required"); //if there is no token alert user
  //if there is a token-validate it
  jwt.verify(token, AT_SECRET, (err, data) => {
    if (err) return res.status(403).send("Inalid token");
    res.status(200).json({ valid: true });
  });
});

//get user's unformation
app.get("/api/v1/information", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.slice(7);

  //check access token exists
  if (!token) return res.status(401).send("Access Token Required");
  //get token's user
  jwt.verify(token, AT_SECRET, (err, data) => {
    console.log(err);
    if (err) return res.status(403).send("Inalid Access token");
    //find user and send user info
    const info = INFORMATION.filter((entry) => entry.name === data.name);

    res.status(200).json(info);
  });
});

//generate new access token
app.post("/users/token", (req, res) => {
  const {
    body: { token: token },
  } = req;

  //check if refresh token exists
  if (!token) return res.status(401).send("Refresh Token Required");
  //check if refresh token is valid (in DB)
  if (!REFRESH_TOKENS.includes(token))
    return res.status(403).send("Invalid Refresh Token");
  //create new refresh token and send to user
  jwt.verify(token, RT_SECRET, (err, data) => {
    if (err) return res.status(403).send("Invalid Refresh Token");
    const newAT = createAccessToken({
      name: data.name,
      email: data.email,
      password: data.password,
      isAdmin: data.isAdmin,
    });
    res.status(200).json({ accessToken: newAT });
  });
});

//logout a user
app.post("/users/logout", (req, res) => {
  const {
    body: { token: token },
  } = req;

  //check there is a refresh token
  if (!token) return res.status(400).send("Refresh Token Required");
  //find token in DB and check it's valid

  const tokenIndex = REFRESH_TOKENS.findIndex((t) => t === token);

  if (tokenIndex === -1) return res.status(400).send("Invalid Refresh Token");
  //delete refreh token from DB
  REFRESH_TOKENS.splice(tokenIndex, -1);
  res.status(200).send("User Logged Out Successfully");
});

app.get("/api/v1/users", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.slice(7);

  //check access token exists
  if (!token) return res.status(401).send("Access Token Required");
  //get token's user
  jwt.verify(token, AT_SECRET, (err, data) => {
    if (err) return res.status(403).send("Inalid Access token");
    if (!data.isAdmin) return res.status(403).send("Inalid Access token");
    //find user and send user info

    res.status(200).json(USERS);
  });
});

app.options("/", (req, res) => {
  const Alloptions = [
    {
      method: "post",
      path: "/users/register",
      description: "Register, Required: email, user, password",
      example: {
        body: { email: "user@email.com", name: "user", password: "password" },
      },
    },
    {
      method: "post",
      path: "/users/login",
      description: "Login, Required: valid email and password",
      example: { body: { email: "user@email.com", password: "password" } },
    },
    {
      method: "post",
      path: "/users/token",
      description: "Renew access token, Required: valid refresh token",
      example: { headers: { token: "*Refresh Token*" } },
    },
    {
      method: "post",
      path: "/users/tokenValidate",
      description: "Access Token Validation, Required: valid access token",
      example: { headers: { authorization: "Bearer *Access Token*" } },
    },
    {
      method: "get",
      path: "/api/v1/information",
      description: "Access user's information, Required: valid access token",
      example: { headers: { authorization: "Bearer *Access Token*" } },
    },
    {
      method: "post",
      path: "/users/logout",
      description: "Logout, Required: access token",
      example: { body: { token: "*Refresh Token*" } },
    },
    {
      method: "get",
      path: "api/v1/users",
      description: "Get users DB, Required: Valid access token of admin user",
      example: { headers: { authorization: "Bearer *Access Token*" } },
    },
  ];
  const authHeader = req.headers["authorization"];

  const token = authHeader && authHeader.slice(7);
  let returnedOptions = [];
  let returnedIndexes = [0, 1];

  if (token) {
    returnedIndexes.push(2);
    jwt.verify(token, AT_SECRET, (err, data) => {
      if (err) return;
      returnedIndexes.push(3, 4, 5);
      if (data.isAdmin) returnedIndexes.push(6);
    });
  }
  returnedOptions = Alloptions.filter((op, i) => returnedIndexes.includes(i));

  res.set("Allow", "OPTIONS, GET, POST").status(200).json(returnedOptions);
});

//helper function
const createAccessToken = (user) => {
  return jwt.sign(user, AT_SECRET, { expiresIn: "10s" });
};

module.exports = app;
