require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const db = require('./database/dbConfig.js');

const server = express();

server.use(express.json());
server.use(cors());
server.use(helmet());

const generateToken = (user) => {
  const payload = {
    username: user.username,
    roles: ['admin','sales'] //should come from database
  };
  const secret = process.env.JWT_SECRET;
  const options = {
    expiresIn: '30m',
  }

  return jwt.sign(payload, secret, options)
}

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
      console.log(id)
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
        //create token 
        const token = generateToken(user)
        res
          .status(200)
          .json({message: `welcome ${user.username}`, token})
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
  //The auth token is normally sent on the authorization header
  const token = req.headers.authorization;
  if(token){
    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
      if(err) {
        res
      .status(401)
      .json({message: 'Invalid Token'})
      } else {
        req.decodedToken = decodedToken;
        next();
      }
    })
  } else {
    res
      .status(401)
      .json({message: 'No token Provided'})
  }
}

const checkRole = (role) => {
  return (req, res, next) => {
    if (req.decodedToken.roles.includes(role)) {
      next()
    } else {
      res
        .status(403)
        .json({message: `you need to be an ${role}`})
    }
  }
}

// protect this route, only authenticated users should see it
server.get('/api/users', protected, async (req, res) => {
  db('users')
    .select('id', 'username')
    .then(users => {
      res.json({users, decodedToken: req.decodedToken});
    })
    .catch(err => res.send(err));
});

server.get('/api/users/me', protected, checkRole('root'), async (req, res) => {
  db('users')
    .where('username', req.decodedToken.username).first()
    .then(user => {
      res.json(user);
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log('\nrunning on port 3300\n'));


// {
// 	"username": "user1",
// 	"password": "password"
// }