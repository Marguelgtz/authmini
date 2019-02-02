const express = require('express');
const cors = require('cors');
const helmet = require('helmet')
const bcrypt = require('bcryptjs')
const session = require('express-session')
const knexSessionStore = require('connect-session-knex')(session)

const db = require('./database/dbConfig.js');

const server = express();

const sessionConfig ={
  name: 'cookie_name', //default name: default is sid(not recomended)
  secret: 'asdjfhalkjdfu0087DWNOIQUWHNNO*(&YX3X' ,//cookie is encrypted using this secret, 
  cookie: {
    maxAge: 1000 * 60 * 10, // 10 minute session in miliseconds
    secure: false,// only send the cookie over https, should be true in production
  },
  httpOnly: true, //Javascript can't touch cookie
  resave: false, //compliance with the law
  saveUninitialized: false, //compliance with the law
  store: new knexSessionStore({
    tablename: 'sessions',
    sidfieldname: 'sid',
    knex: db,
    createtable: true,
    clearInterval: 1000 * 60 * 15,
  })
}

server.use(express.json());
server.use(cors());
server.use(helmet())
server.use(session(sessionConfig))

server.post('/api/register', (req, res) => {
  // grab username/password from body
  const creds = req.body
  // generate the hash from the user password
  const hash = bcrypt.hashSync(creds.password, 14) //rounds 2^x
  // override the user.password with the hash
  creds.password = hash
  // save the user to the database
  db('users').insert(creds)
    .then(ids => {
      res
        .status(201)
        .json(ids)
    })
    .catch(err => {
      res
        .status(500)
        .json(err)
    })
})

server.post('/api/login', (req, res) => {
  // grab username/password from body
  const creds = req.body
  // comprare the hash from the user password
  db('users').where('username', creds.username).first()
    .then(user => {
      if(user && bcrypt.compareSync(creds.password, user.password)) {
        //Password match
        req.session.user = user;
        res
          .status(200)
          .json({message: `welcome ${user.username}`})
      } else {
        res
          .status(401)
          .json({message: 'failed to authenticate'})
      }
    })
    .catch(err => {
      res
        .status(500)
        .json(err)
    })
})

server.get('/', (req, res) => {
  res.send('Its Alive!');
});

const protected = (req, res, next) => {
  //if the user is logged in next()
  if(req.session && req.session.user) {
    next()
  } else {
    res
      .status(401)
      .json({message: 'not logged in'})
  }
}

// protect this route, only authenticated users should see it
server.get('/api/users', protected, async (req, res) => {
  db('users')
    .select('id', 'username')
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// Logout
server.get('/api/logout', (req, res) => {
  if(req.session) {
    req.session.destroy()
    res
      .status(200)
      .json({message: 'session destroyed'})
  } else {
    res
      .json({message: 'Logged out already'})
  }
})


server.listen(3300, () => console.log('\nrunning on port 3300\n'));


// {
// 	"username": "user1",
// 	"password": "password"
// }