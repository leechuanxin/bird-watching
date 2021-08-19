import express from 'express';
import pg from 'pg';
import cookieParser from 'cookie-parser';
import moment from 'moment';

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
// To parse cookie string value in the header into a JavaScript Object
app.use(cookieParser());

app.get('/note', (request, response) => {
  response.render('note', {});
});

app.post('/note', (request, response) => {
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
  ];
  const query = 'INSERT INTO notes (created_date, created_time, last_updated_date, last_updated_time, date, time, duration_hour, duration_minute, duration_second, behaviour, number_of_birds, flock_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *';
  pool.query(query, input, (error, result) => {
    if (error) {
      response.status(503).send('Error executing query');
    } else {
      response.send('success!');
    }
  });
});

app.listen(3004);
