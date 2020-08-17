const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const usersRouter = require("./users/users-router.js");
const authRouter = require("./auth/auth-router.js");
const dbConnection = require("./database/connection.js");
const protected = require("./auth/protected-mw.js");

const server = express();

const sessionConfiguration = {
	name: "monster",
	secret: "keep it secret, keep it safe!",
	cookie: {
		maxAge: 1000 * 60 * 10,
		// ten minute lifespan on the cookie, can make any length of time sometimes weeks depending on what system you are working with
		secure: process.env.COOKIE_SECURE || false,
		// if true cookie is only sent over HTTPS which is the encrypted version of HTTP
		httpOnly: true,
		// means JS cannot touch this cookie
	},
	resave: false,
	saveUninitialized: true,
	// GDPR Compliance -READ ABOUT THIS- , the client should drive this , company will have guidelines based on client preferences
	store: new KnexSessionStore({
		knex: dbConnection,
		tablename: "sessions",
		sidfieldname: "sid",
		createtable: true,
		clearInterval: 1000 * 60 * 60, // delete expired sessions every hour
	}),
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfiguration));

server.use("/api/users", protected, usersRouter);
server.use("/api/auth", authRouter);

server.get("/", (req, res) => {
	res.json({ api: "up" });
});

// {
//   "data": {
//       "id": 1,
//       "username": "sam",
//       "password": "$2a$08$J9hbDZKif5HcuX8fb04oIuhLt2etEpjJ0FjiFuIZLepiG1XUAZg1O",
//       "role": null
//   }
// }

server.get("/hash", (req, res) => {
	try {
		// read a password prop from the headers
		const password = req.headers.password;

		// hash the password and it back. both the password and the hash
		const rounds = process.env.HASH_ROUNDS || 8; // 8 is the number of rounds as 2 ^ 8
		const hash = bcrypt.hashSync(password, rounds);

		res.status(200).json({ password, hash });
	} catch (error) {
		res.status(500).json({ error: error.message });
	}
});

module.exports = server;
