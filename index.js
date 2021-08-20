import express from 'express';
import pg from 'pg';
import methodOverride from 'method-override';
import cookieParser from 'cookie-parser';
import moment from 'moment';
import jsSHA from 'jssha';

// Initialise DB connection
const { Pool } = pg;
const pgConnectionConfigs = {
  user: 'chuanxin',
  host: 'localhost',
  database: 'birding',
  port: 5432, // Postgres server always runs on this port by default
};
const pool = new Pool(pgConnectionConfigs);

const app = express();
// Set view engine
app.set('view engine', 'ejs');
// To receive POST request body data in request.body
app.use(express.urlencoded({ extended: false }));
// Override POST requests with query param ?_method=PUT to be PUT requests
app.use(methodOverride('_method'));
// To parse cookie string value in the header into a JavaScript Object
app.use(cookieParser());

app.get('/', (request, response) => {
  if (
    !request.cookies.loggedIn
    || Number.isNaN(Number(request.cookies.loggedIn))
    || Number(request.cookies.loggedIn) < 1
  ) {
    response.redirect('/login');
  } else {
    const query = 'SELECT notes.id, notes.created_user_id, users.id AS matched_user_id, users.email FROM notes INNER JOIN users ON notes.created_user_id = users.id';
    pool.query(query, (error, result) => {
      if (error) {
        response.status(503).send('Error executing query');
      } else {
        response.render('index', { notes: result.rows, session: { sessionId: request.cookies.loggedIn } });
      }
    });
  }
});

app.get('/login', (request, response) => {
  if (
    request.cookies.loggedIn && Number(request.cookies.loggedIn) >= 1
  ) {
    response.redirect('/');
  } else {
    response.render('login', { session: { sessionId: request.cookies.loggedIn } });
  }
});

app.post('/login', (request, response) => {
  const values = [request.body.email];

  pool.query('SELECT * from users WHERE email=$1', values, (error, result) => {
    if (error) {
      response.status(503).send('Error executing query!');
      return;
    }

    if (result.rows.length === 0) {
      // we didnt find a user with that email.
      // the error for password and user are the same.
      // don't tell the user which error they got for security reasons,
      // otherwise people can guess if a person is a user of a given service.
      response.status(403).send('sorry!');
      return;
    }

    // get user record from results
    const user = result.rows[0];
    // initialise SHA object
    // eslint-disable-next-line new-cap
    const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
    // input the password from the request to the SHA object
    shaObj.update(request.body.password);
    // get the hashed value as output from the SHA object
    const hashedPassword = shaObj.getHash('HEX');

    // If the user's hashed password in the database
    // does not match the hashed input password, login fails
    if (user.password !== hashedPassword) {
      // the error for incorrect email and incorrect password are the same for security reasons.
      // This is to prevent detection of whether a user has an account for a given service.
      response.status(403).send('login failed!');
      return;
    }

    // The user's password hash matches that in the DB and we authenticate the user.
    response.cookie('loggedIn', result.rows[0].id);
    response.redirect('/');
  });
});

app.get('/signup', (request, response) => {
  if (
    request.cookies.loggedIn && Number(request.cookies.loggedIn) >= 1
  ) {
    response.redirect('/');
  } else {
    response.render('signup', { session: { sessionId: request.cookies.loggedIn } });
  }
});

app.post('/signup', (request, response) => {
  // initialise the SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // input the password from the request to the SHA object
  shaObj.update(request.body.password);
  // get the hashed password as output from the SHA object
  const hashedPassword = shaObj.getHash('HEX');

  // store the hashed password in our DB
  const values = [request.body.email, hashedPassword];
  pool.query(
    'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
    values,
    (error) => {
      // ...
      if (error) {
        response.send('DB write error');
        return;
      }

      if (!error) {
        response.redirect('/login');
      }
    },
  );
});

app.delete('/logout', (request, response) => {
  if (request.cookies.loggedIn) {
    response.clearCookie('loggedIn');
    response.redirect('/');
  } else {
    response.status(403).send('Error logging out!');
  }
});

app.get('/note', (request, response) => {
  if (
    !request.cookies.loggedIn
    || Number.isNaN(Number(request.cookies.loggedIn))
    || Number(request.cookies.loggedIn) < 1
  ) {
    response.redirect('/login');
  } else {
    response.render('newnote', { session: { sessionId: request.cookies.loggedIn } });
  }
});

app.post('/note', (request, response) => {
  if (
    !request.cookies.loggedIn
    || Number.isNaN(Number(request.cookies.loggedIn))
    || Number(request.cookies.loggedIn) < 1
  ) {
    response.status(403).send('You need to be logged in!');
  } else {
    const fields = Object.values(request.body);
    const currentTime = moment();
    const createdDate = currentTime.format('YYYY-MM-DD');
    const createdTime = currentTime.format('HH:mm:ss');
    const input = [
      createdDate,
      createdTime,
      createdDate,
      createdTime,
      ...fields,
      request.cookies.loggedIn,
    ];
    const query = 'INSERT INTO notes (created_date, created_time, last_updated_date, last_updated_time, date, time, duration_hour, duration_minute, duration_second, behaviour, number_of_birds, flock_type, created_user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *';
    pool.query(query, input, (error) => {
      if (error) {
        response.status(503).send('Error executing query');
      } else {
        response.send('success!');
      }
    });
  }
});

app.get('/note/:id', (request, response) => {
  if (
    !request.cookies.loggedIn
    || Number.isNaN(Number(request.cookies.loggedIn))
    || Number(request.cookies.loggedIn) < 1
  ) {
    response.redirect('/login');
  } else {
    const { id } = request.params;
    const query = `SELECT * FROM notes WHERE id=${id}`;
    pool.query(query, (error, result) => {
      if (error) {
        console.log('Error executing query', error.stack);
        response.status(503).send(`Error executing query: ${result.rows}`);
        return;
      }

      if (result.rows.length === 0) {
      // we didnt find this id
        response.status(404).send('sorry, id not found!');
      } else {
        response.render('note', { note: result.rows[0], session: { sessionId: request.cookies.loggedIn } });
      }
    });
  }
});

app.listen(3004);
