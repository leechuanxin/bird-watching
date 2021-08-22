import express from 'express';
import pg from 'pg';
import methodOverride from 'method-override';
import cookieParser from 'cookie-parser';
import moment from 'moment';
import jsSHA from 'jssha';
import dotenv from 'dotenv';

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
// Set public folder for static files
app.use(express.static('public'));
// Set up Node to pull process env values from .env files
dotenv.config();

// GLOBAL CONSTANTS
const MAX_SUMMARY_LENGTH = 50;
const { SALT } = process.env;

app.get('/', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if hashed value doesn't match, return 403.
  if (hashedCookieString !== loggedIn) {
    response.redirect('/login');
  } else {
    let query = 'SELECT notes.id, notes.behaviour, notes.created_date, notes.created_time, notes.summary, notes.created_user_id, users.id AS matched_user_id, users.email FROM notes INNER JOIN users ON notes.created_user_id = users.id';
    let sortStr = '';
    let sortByParam = '';

    switch (request.query.sort_by) {
      case 'created_time_oldest':
        sortStr = ' ORDER BY created_date ASC, created_time ASC';
        sortByParam = request.query.sort_by;
        break;
      case 'summary_asc':
        sortStr = ' ORDER BY summary ASC';
        sortByParam = request.query.sort_by;
        break;
      case 'summary_desc':
        sortStr = ' ORDER BY summary DESC';
        sortByParam = request.query.sort_by;
        break;
      case 'email_asc':
        sortStr = ' ORDER BY email ASC, created_date DESC, created_time DESC';
        sortByParam = request.query.sort_by;
        break;
      case 'email_desc':
        sortStr = ' ORDER BY email DESC, created_date DESC, created_time DESC';
        sortByParam = request.query.sort_by;
        break;
      default:
        sortStr = ' ORDER BY created_date DESC, created_time DESC';
        break;
    }

    query += sortStr;
    pool.query(query, (error, result) => {
      if (error) {
        response.status(503).send('Error executing query');
      } else {
        const rowsFmt = (result.rows.length > 0) ? result.rows.map((row) => {
          const createdDateFmt = moment(row.created_date).format('YYYY-MM-DD').split('-');
          const createdTimeFmt = row.created_time.split(':');
          const createdDateTimeUtc = moment.utc(
            Date.UTC(
              Number(createdDateFmt[0]),
              Number(createdDateFmt[1]) - 1,
              Number(createdDateFmt[2]),
              Number(createdTimeFmt[0]),
              Number(createdTimeFmt[1]),
              Number(createdTimeFmt[2]),
            ),
          );
          const createdDateTimeLocal = createdDateTimeUtc.local().format('MMMM Do, YYYY HH:mm A');

          return {
            ...row,
            createdDateTime: createdDateTimeLocal,
          };
        }) : result.rows;
        response.render('index', { notes: rowsFmt, session: { sessionId: userId }, sortBy: { param: sortByParam } });
      }
    });
  }
});

app.get('/login', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if match, redirect straight to index
  if (hashedCookieString === loggedIn) {
    response.redirect('/');
  } else {
    response.render('login', { session: { sessionId: userId } });
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

    // create new SHA object for cookie
    // eslint-disable-next-line new-cap
    const shaObjCookie = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
    // create an unhashed cookie string based on user ID and salt
    const unhashedCookieString = `${result.rows[0].id}-${SALT}`;
    // generate a hashed cookie string using SHA object
    shaObjCookie.update(unhashedCookieString);
    const hashedCookieString = shaObjCookie.getHash('HEX');
    // set the loggedIn and userId cookies in the response
    // The user's password hash matches that in the DB and we authenticate the user.
    response.cookie('loggedIn', hashedCookieString);
    response.cookie('userId', result.rows[0].id);
    response.redirect('/');
  });
});

app.get('/signup', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if match, redirect straight to index
  if (hashedCookieString === loggedIn) {
    response.redirect('/');
  } else {
    response.render('signup', { session: { sessionId: userId } });
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
    response.clearCookie('userId');
    response.clearCookie('loggedIn');
    response.redirect('/');
  } else {
    response.status(403).send('Error logging out!');
  }
});

app.get('/note', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, redirect straight to login
  if (hashedCookieString !== loggedIn) {
    response.redirect('/login');
  } else {
    const query = 'SELECT * FROM species';
    pool.query(query, (error, result) => {
      if (error) {
        response.status(503).send('Error executing query');
      } else {
        const typeObj = { type: { name: 'new' } };
        response.render('newnote', {
          note: {},
          session: { sessionId: userId },
          species: { speciesList: result.rows, currentSpecies: 0 },
          ...typeObj,
        });
      }
    });
  }
});

app.post('/note', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, status 403 forbidden
  if (hashedCookieString !== loggedIn) {
    response.status(403).send('You need to be logged in!');
  } else {
    // retrieve field values from duration onwards (ignore date and time)
    const fields = Object.values(request.body).slice(2);
    const currentTime = new Date();
    const currentTimeUtc = moment.utc(
      Date.UTC(
        currentTime.getUTCFullYear(),
        currentTime.getUTCMonth(),
        currentTime.getUTCDate(),
        currentTime.getUTCHours(),
        currentTime.getUTCMinutes(),
        currentTime.getUTCSeconds(),
      ),
    );
    const createdDate = currentTimeUtc.format('YYYY-MM-DD');
    const createdTime = currentTimeUtc.format('HH:mm:ss');
    const dateTime = new Date(`${request.body.date}T${request.body.time}:00`);
    const dateTimeUtc = moment.utc(
      Date.UTC(
        dateTime.getUTCFullYear(),
        dateTime.getUTCMonth(),
        dateTime.getUTCDate(),
        dateTime.getUTCHours(),
        dateTime.getUTCMinutes(),
        dateTime.getUTCSeconds(),
      ),
    );
    const dateUtc = dateTimeUtc.format('YYYY-MM-DD');
    const timeUtc = dateTimeUtc.format('HH:mm:ss');

    const summary = (request.body && request.body.behaviour && request.body.behaviour.trim() !== '' && request.body.behaviour.length > MAX_SUMMARY_LENGTH) ? request.body.behaviour.substring(0, MAX_SUMMARY_LENGTH).concat('...') : request.body.behaviour;
    const input = [
      createdDate,
      createdTime,
      createdDate,
      createdTime,
      ...fields,
      dateUtc,
      timeUtc,
      summary,
      request.cookies.userId,
    ];
    const query = 'INSERT INTO notes (created_date, created_time, last_updated_date, last_updated_time, duration_hour, duration_minute, duration_second, behaviour, number_of_birds, flock_type, species_id, date, time, summary, created_user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING *';
    pool.query(query, input, (error, result) => {
      if (error) {
        response.status(503).send('Error executing query');
      } else {
        response.redirect(`/note/${result.rows[0].id}`);
      }
    });
  }
});

app.get('/note/:id', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, redirect straight to login
  if (hashedCookieString !== loggedIn) {
    response.redirect('/login');
  } else {
    const { id } = request.params;
    const query = `SELECT notes.id, notes.created_date, notes.created_time, notes.last_updated_date, notes.last_updated_time, notes.date, notes.time, notes.duration_hour, notes.duration_minute, notes.duration_second, notes.behaviour, notes.number_of_birds, notes.flock_type, notes.created_user_id, notes.summary, notes.species_id, species.name, species.scientific_name FROM notes INNER JOIN species ON notes.species_id = species.id WHERE notes.id=${id}`;
    pool.query(query, (error, result) => {
      if (error) {
        response.status(503).send(`Error executing query: ${result.rows}`);
        return;
      }

      if (result.rows.length === 0) {
      // we didnt find this id
        response.status(404).send('sorry, id not found!');
      } else {
        const dateFmt = moment(result.rows[0].date).format('YYYY-MM-DD').split('-');
        const timeFmt = result.rows[0].time.split(':');
        const dateTimeUtc = moment.utc(
          Date.UTC(
            Number(dateFmt[0]),
            Number(dateFmt[1]) - 1,
            Number(dateFmt[2]),
            Number(timeFmt[0]),
            Number(timeFmt[1]),
            Number(timeFmt[2]),
          ),
        );
        const dateTimeLocal = dateTimeUtc.local();

        response.render('note', {
          note: {
            ...result.rows[0],
            date: dateTimeLocal.format('MMMM Do, YYYY'),
            time: dateTimeLocal.format('HH:mm A'),
          },
          session: { sessionId: userId },
        });
      }
    });
  }
});

app.get('/note/:id/edit', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, redirect straight to login
  if (hashedCookieString !== loggedIn) {
    response.redirect('/login');
  } else {
    const query = 'SELECT * FROM species';
    pool.query(query, (error, result) => {
      if (error) {
        response.status(503).send('Error executing query: can\'t retrieve species list.');
      } else {
        const typeObj = { type: { name: 'edit' } };
        const speciesList = { speciesList: result.rows };

        const { id } = request.params;
        const getFormQuery = `SELECT notes.id, notes.created_date, notes.created_time, notes.last_updated_date, notes.last_updated_time, notes.date, notes.time, notes.duration_hour, notes.duration_minute, notes.duration_second, notes.behaviour, notes.number_of_birds, notes.flock_type, notes.created_user_id, notes.summary, notes.species_id, species.name, species.scientific_name FROM notes INNER JOIN species ON notes.species_id = species.id WHERE notes.id=${id}`;
        pool.query(getFormQuery, (getFormError, getFormResult) => {
          if (getFormError) {
            response.status(503).send(`Error executing query: ${getFormResult.rows}`);
            return;
          }

          if (getFormResult.rows.length === 0) {
            // we didnt find this id
            response.status(404).send('sorry, id not found!');
          } else {
            const dateFmt = moment(getFormResult.rows[0].date).format('YYYY-MM-DD').split('-');
            const timeFmt = getFormResult.rows[0].time.split(':');
            const dateTimeUtc = moment.utc(
              Date.UTC(
                Number(dateFmt[0]),
                Number(dateFmt[1]) - 1,
                Number(dateFmt[2]),
                Number(timeFmt[0]),
                Number(timeFmt[1]),
                Number(timeFmt[2]),
              ),
            );
            const dateTimeLocal = dateTimeUtc.local();
            response.render('newnote', {
              note: {
                ...getFormResult.rows[0],
                date: dateTimeLocal.format('YYYY-MM-DD'),
                time: dateTimeLocal.format('HH:mm:ss'),
              },
              species: {
                ...speciesList,
                currentSpecies: getFormResult.rows[0].species_id || 0,
              },
              session: { sessionId: userId },
              ...typeObj,
            });
          }
        });
      }
    });
  }
});

app.put('/note/:id/edit', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, status 403 forbidden
  if (hashedCookieString !== loggedIn) {
    response.status(403).send('You need to be logged in!');
  } else {
    const firstQuery = `SELECT * FROM notes WHERE id=${request.params.id}`;
    pool.query(firstQuery, (firstQueryError, firstQueryResult) => {
      if (!firstQueryError) {
        // eslint-disable-next-line new-cap
        const firstQueryShaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
        const unhashedCreatedUserString = `${firstQueryResult.rows[0].created_user_id}-${SALT}`;
        firstQueryShaObj.update(unhashedCreatedUserString);
        const hashedCreatedUserString = firstQueryShaObj.getHash('HEX');
        if (hashedCreatedUserString !== hashedCookieString) {
          response.status(403).send('You cannot edit a note where you aren\'t the owner!');
        } else {
          const fields = Object.values(request.body);
          const currentTime = moment();
          const lastUpdatedDate = currentTime.format('YYYY-MM-DD');
          const lastUpdatedTime = currentTime.format('HH:mm:ss');
          const summary = (request.body && request.body.behaviour && request.body.behaviour.trim() !== '' && request.body.behaviour.length > MAX_SUMMARY_LENGTH) ? request.body.behaviour.substring(0, MAX_SUMMARY_LENGTH).concat('...') : request.body.behaviour;
          const input = [
            lastUpdatedDate,
            lastUpdatedTime,
            ...fields,
            summary,
          ];
          const query = `UPDATE notes SET last_updated_date=$1, last_updated_time=$2, date=$3, time=$4, duration_hour=$5, duration_minute=$6, duration_second=$7, behaviour=$8, number_of_birds=$9, flock_type=$10, species_id=$11, summary=$12 WHERE id=${request.params.id} RETURNING *`;
          pool.query(query, input, (error, result) => {
            if (error) {
              response.status(503).send('Error executing query');
            } else {
              response.redirect(`/note/${result.rows[0].id}`);
            }
          });
        }
      } else {
        response.status(503).send('Error executing query');
      }
    });
  }
});

app.delete('/note/:id/delete', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, status 403 forbidden
  if (hashedCookieString !== loggedIn) {
    response.status(403).send('You need to be logged in!');
  } else {
    const firstQuery = `SELECT * FROM notes WHERE id=${request.params.id}`;
    pool.query(firstQuery, (firstQueryError, firstQueryResult) => {
      if (!firstQueryError) {
        // eslint-disable-next-line new-cap
        const firstQueryShaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
        const unhashedCreatedUserString = `${firstQueryResult.rows[0].created_user_id}-${SALT}`;
        firstQueryShaObj.update(unhashedCreatedUserString);
        const hashedCreatedUserString = firstQueryShaObj.getHash('HEX');
        if (hashedCreatedUserString !== hashedCookieString) {
          response.status(403).send('You cannot delete a note where you aren\'t the owner!');
        } else {
          const query = `DELETE FROM notes WHERE id=${request.params.id}`;
          pool.query(query, (error) => {
            if (error) {
              response.status(503).send('Error executing query');
            } else {
              response.redirect('/');
            }
          });
        }
      } else {
        response.status(503).send('Error executing query');
      }
    });
  }
});

app.get('/users/:id', (request, response) => {
  const { loggedIn, userId } = request.cookies;
  // create new SHA object
  // eslint-disable-next-line new-cap
  const shaObj = new jsSHA('SHA-512', 'TEXT', { encoding: 'UTF8' });
  // reconstruct the hashed cookie string
  const unhashedCookieString = `${userId}-${SALT}`;
  shaObj.update(unhashedCookieString);
  const hashedCookieString = shaObj.getHash('HEX');

  // verify if the generated hashed cookie string matches the request cookie value.
  // if not match, redirect straight to login
  if (hashedCookieString !== loggedIn) {
    response.redirect('/login');
  } else {
    const { id } = request.params;
    const query = `SELECT * FROM users WHERE id=${id}`;
    pool.query(query, (error, result) => {
      if (error) {
        response.status(503).send(`Error executing query: ${result.rows}`);
        return;
      }

      if (result.rows.length === 0) {
      // we didnt find this id
        response.status(404).send('sorry, id not found!');
      } else {
        const notesQuery = `SELECT * FROM notes WHERE created_user_id=${id}`;
        pool.query(notesQuery, (notesQueryError, notesQueryResult) => {
          if (notesQueryError) {
            response.status(503).send(`Error executing query: ${notesQueryResult.rows}`);
          } else if (notesQueryResult.rows.length === 0) {
            // we didnt find this id
            response.status(404).send('sorry, no notes found!');
          } else {
            response.render('user_notes', { notes: notesQueryResult.rows, session: { sessionId: userId } });
          }
        });
      }
    });
  }
});

app.listen(3004);
